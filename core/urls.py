
from django.contrib import admin
from django.urls import path, include
from .views import saludos_api

urlpatterns = [
    path('', saludos_api, name='api-raiz'),
    path('admin/', admin.site.urls),
    path('api/', include('usuarios.urls')),
]
