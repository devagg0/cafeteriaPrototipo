from django.contrib import admin
from .models import Notificacion


@admin.register(Notificacion)
class NotificacionAdmin(admin.ModelAdmin):
    list_display = ('titulo', 'usuario_destino', 'leido', 'fecha_creacion')
    search_fields = ('titulo', 'mensaje', 'usuario_destino__nombre')
    list_filter = ('leido', 'fecha_creacion')
