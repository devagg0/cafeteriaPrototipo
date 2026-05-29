
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from .views import saludos_api


urlpatterns = [
    path('', saludos_api, name='api-raiz'),
    path('admin/', admin.site.urls),
    path('api/', include('usuarios.urls')),
    path('api/', include('reservas.urls')),
    path('api/', include('pedidos.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

