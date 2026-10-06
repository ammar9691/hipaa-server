#!/bin/bash
# Web stack for WordPress: nginx + PHP-FPM + MariaDB, SELinux enforcing.
# The site is prepared but NOT published: nginx answers 444 until a domain and TLS certificate are set (08-site-tls.sh).
set -uo pipefail
WP_ROOT=/var/www/wordpress

echo "== packages"
dnf -y -q install nginx mariadb-server php-fpm php-mysqlnd php-gd php-xml php-mbstring php-intl php-zip php-opcache php-json tar policycoreutils-python-utils 2>&1 | tail -1
rpm -q nginx mariadb-server php-fpm | tr '\n' ' '; echo

echo "== mariadb: local only"
cat > /etc/my.cnf.d/90-hardening.cnf <<'CNF'
[mysqld]
bind-address = 127.0.0.1
local-infile = 0
skip-symbolic-links
CNF
systemctl enable --now mariadb
mysql <<'SQL'
DELETE FROM mysql.global_priv WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
FLUSH PRIVILEGES;
SQL
if [ ! -f "$WP_ROOT/wp-config.php" ]; then
  DBPASS=$(openssl rand -base64 30 | tr -d '/+=' | cut -c1-32)
  mysql -e "CREATE DATABASE IF NOT EXISTS wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS 'wp'@'localhost' IDENTIFIED BY '$DBPASS'; ALTER USER 'wp'@'localhost' IDENTIFIED BY '$DBPASS'; GRANT ALL PRIVILEGES ON wordpress.* TO 'wp'@'localhost'; FLUSH PRIVILEGES;"

  echo "== wordpress (checksum verified)"
  cd /tmp && curl -sSLO https://wordpress.org/latest.tar.gz && curl -sSL https://wordpress.org/latest.tar.gz.sha1 -o latest.sha1
  [ "$(sha1sum latest.tar.gz | cut -d' ' -f1)" = "$(cat latest.sha1)" ] || { echo "WORDPRESS CHECKSUM MISMATCH"; exit 4; }
  mkdir -p /var/www && tar -xzf latest.tar.gz -C /var/www && rm -f latest.tar.gz latest.sha1
  cd "$WP_ROOT" && cp wp-config-sample.php wp-config.php
  sed -i "s/database_name_here/wordpress/; s/username_here/wp/; s/password_here/$DBPASS/" wp-config.php
  SALTS=$(curl -sS https://api.wordpress.org/secret-key/1.1/salt/)
  sed -i "/AUTH_KEY/,/NONCE_SALT/d" wp-config.php
  printf '%s\n' "$SALTS" > /tmp/salts
  sed -i "/DB_COLLATE/r /tmp/salts" wp-config.php && rm -f /tmp/salts
  cat >> /tmp/wpextra <<'PHP'
define( 'DISALLOW_FILE_EDIT', true );
define( 'FORCE_SSL_ADMIN', true );
define( 'WP_AUTO_UPDATE_CORE', 'minor' );
PHP
  sed -i "/DB_COLLATE/r /tmp/wpextra" wp-config.php && rm -f /tmp/wpextra
fi

echo "== ownership + SELinux labels"
chown -R root:root "$WP_ROOT"
chown -R apache:apache "$WP_ROOT/wp-content"
chown root:apache "$WP_ROOT/wp-config.php" && chmod 640 "$WP_ROOT/wp-config.php"
semanage fcontext -a -t httpd_sys_content_t "$WP_ROOT(/.*)?" 2>/dev/null || true
semanage fcontext -a -t httpd_sys_rw_content_t "$WP_ROOT/wp-content(/.*)?" 2>/dev/null || true
restorecon -R "$WP_ROOT"
setsebool -P httpd_can_network_connect 1

echo "== php hardening"
cat > /etc/php.d/90-hardening.ini <<'INI'
expose_php = Off
display_errors = Off
log_errors = On
allow_url_include = Off
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
upload_max_filesize = 16M
post_max_size = 16M
INI
systemctl enable --now php-fpm

echo "== nginx: closed by default"
cp -n /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak-$(date +%Y%m%d)
cat > /etc/nginx/conf.d/00-default-closed.conf <<'NGX'
server_tokens off;
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 444; }
}
NGX
mkdir -p /var/www/acme && restorecon -R /var/www/acme
sed -i '/^    server {/,/^    }/d' /etc/nginx/nginx.conf
nginx -t 2>&1 | tail -2 && systemctl enable --now nginx && systemctl reload nginx

echo "== state"
for s in nginx php-fpm mariadb; do echo "$s: $(systemctl is-active $s)"; done
ss -tlnp | awk 'NR>1{print $4, $6}'
php -v | head -1; mysql -V; nginx -v 2>&1
mysql -N -e "SELECT CONCAT(User,'@',Host) FROM mysql.global_priv"
ls -ld "$WP_ROOT" "$WP_ROOT/wp-config.php" "$WP_ROOT/wp-content"
curl -s -o /dev/null -w 'http on localhost: %{http_code}\n' http://127.0.0.1/ || echo "http on localhost: connection closed (444, expected)"
getenforce; ausearch -m avc -ts recent 2>/dev/null | grep -c denied
df -h / | tail -1
