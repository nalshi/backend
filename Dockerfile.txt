FROM php:8.2-apache
RUN docker-php-ext-install pdo pdo_mysql mysqli
RUN a2enmod rewrite
COPY . /var/www/html/
ENV APACHE_DOCUMENT_ROOT /var/www/html/public_html
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf
RUN sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# إعطاء صلاحيات الكتابة والقراءة للسيرفر (مهم جداً لنظام الكاش الخاص بك)
RUN chown -R www-data:www-data /var/www/html/

EXPOSE 80
