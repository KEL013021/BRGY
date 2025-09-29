FROM php:8.2-apache

# Install dependencies
RUN apt-get update && apt-get install -y \
    libpng-dev libjpeg-dev libfreetype6-dev \
    libonig-dev libzip-dev unzip git openssl \
    && docker-php-ext-configure gd --with-jpeg \
    && docker-php-ext-install mysqli gd zip

# Enable Apache modules
RUN a2enmod rewrite ssl headers

# Copy project files
WORKDIR /var/www/html
COPY . /var/www/html

# Create upload folders
RUN mkdir -p /var/www/html/pdf_templates /var/www/html/images/services /var/www/html/uploads \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 775 /var/www/html/pdf_templates /var/www/html/images/services /var/www/html/uploads

# PHP config for uploads
RUN { \
        echo "file_uploads = On"; \
        echo "memory_limit = 256M"; \
        echo "upload_max_filesize = 20M"; \
        echo "post_max_size = 25M"; \
        echo "max_execution_time = 300"; \
    } > /usr/local/etc/php/conf.d/uploads.ini

# Generate self-signed SSL certificate
RUN mkdir -p /etc/apache2/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/apache.key \
    -out /etc/apache2/ssl/apache.crt \
    -subj "/C=PH/ST=Manila/L=QC/O=BRGYGO/OU=IT/CN=localhost"

# Add Apache SSL config
RUN echo "\
<VirtualHost *:443>\n\
    DocumentRoot /var/www/html\n\
    SSLEngine on\n\
    SSLCertificateFile /etc/apache2/ssl/apache.crt\n\
    SSLCertificateKeyFile /etc/apache2/ssl/apache.key\n\
</VirtualHost>" > /etc/apache2/sites-available/default-ssl.conf \
    && a2ensite default-ssl

EXPOSE 80 443
