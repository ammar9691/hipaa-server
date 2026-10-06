#!/bin/bash
# Publish the WordPress site on a domain with a Let's Encrypt certificate, TLS 1.2+/1.3 only, HSTS and
# security headers, then complete the WordPress install server-side so the open install wizard is never exposed.
# Usage: DOMAIN=hipaa.example.com ADMIN_EMAIL=you@example.com bash 08-site-tls.sh
set -uo pipefail
DOMAIN=${DOMAIN:?set DOMAIN}
ADMIN_EMAIL=${ADMIN_EMAIL:?set ADMIN_EMAIL}
WP_ROOT=/var/www/wordpress
WP_ADMIN=${WP_ADMIN:-ammar}

echo "== dns check"
IP=$(curl -s -H "X-aws-ec2-metadata-token: $(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/public-ipv4)
RES=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | head -1)
echo "$DOMAIN -> $RES (server $IP)"
[ "$RES" = "$IP" ] || { echo "DNS NOT POINTING HERE YET"; exit 5; }

echo "== certbot"
rpm -q certbot &>/dev/null || dnf -y -q install certbot 2>&1 | tail -1
if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
  certbot certonly --webroot -w /var/www/acme -d "$DOMAIN" -m "$ADMIN_EMAIL" --agree-tos --no-eff-email -n 2>&1 | grep -E 'Successfully|error|Error' | head -3
fi
ls /etc/letsencrypt/live/"$DOMAIN"/fullchain.pem || exit 6
systemctl enable --now certbot-renew.timer 2>/dev/null; systemctl is-active certbot-renew.timer
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'HOOK'
#!/bin/bash
systemctl reload nginx
HOOK
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

echo "== nginx site"
cat > /etc/nginx/conf.d/10-"$DOMAIN".conf <<NGX
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $DOMAIN;
    root $WP_ROOT;
    index index.php;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    client_max_body_size 16m;
    access_log /var/log/nginx/$DOMAIN.access.log;
    error_log  /var/log/nginx/$DOMAIN.error.log;

    location ~ /\. { deny all; }
    location = /xmlrpc.php { deny all; }
    location ~* ^/wp-content/uploads/.*\.php\$ { deny all; }
    location ~* \.(?:ini|log|sh|sql|bak)\$ { deny all; }
    location / { try_files \$uri \$uri/ /index.php?\$args; }
    location ~ \.php\$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php-fpm/www.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param HTTPS on;
    }
}
NGX
nginx -t 2>&1 | tail -1 && systemctl reload nginx

echo "== wordpress install (server-side, so the wizard is never open to the internet)"
if ! mysql -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='wordpress' AND table_name='wp_options'" | grep -q 1; then
  WPPASS=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)
  CODE=$(curl -s -o /tmp/wp-install.html -w '%{http_code}' "https://$DOMAIN/wp-admin/install.php?step=2" \
    --data-urlencode "weblog_title=HIPAA Server Demo" --data-urlencode "user_name=$WP_ADMIN" \
    --data-urlencode "admin_password=$WPPASS" --data-urlencode "admin_password2=$WPPASS" \
    --data-urlencode "pw_weak=0" --data-urlencode "admin_email=$ADMIN_EMAIL" --data-urlencode "blog_public=0" --data-urlencode "Submit=Install")
  echo "install http=$CODE $(grep -o 'Success!' /tmp/wp-install.html | head -1)"
  rm -f /tmp/wp-install.html
  install -m 600 /dev/null /root/wp-admin-initial-password
  printf 'user: %s\npassword: %s\nChange it after first login, then delete this file.\n' "$WP_ADMIN" "$WPPASS" > /root/wp-admin-initial-password
fi
mysql -N -e "SELECT option_value FROM wordpress.wp_options WHERE option_name IN ('siteurl','blog_public')"

echo "== checks"
curl -s -o /dev/null -w 'http  -> %{http_code} %{redirect_url}\n' "http://$DOMAIN/"
curl -s -o /dev/null -w 'https -> %{http_code}\n' "https://$DOMAIN/"
curl -s -o /dev/null -w 'xmlrpc -> %{http_code}\n' "https://$DOMAIN/xmlrpc.php"
curl -sI "https://$DOMAIN/" | grep -iE '^(strict-transport|x-content-type|x-frame|referrer|server):'
echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | grep -E 'Protocol|Verify return'
ausearch -m avc -ts recent 2>/dev/null | grep -c denied; true
