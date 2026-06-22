from django.contrib import admin
from .models import Promocion

@admin.register(Promocion)
class PromocionAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'codigo',
        'nombre',
        'tipo_descuento',
        'valor_descuento',
        'fecha_inicio',
        'fecha_fin',
        'activa',
        'created_at',
    )
    list_filter = ('activa', 'tipo_descuento', 'fecha_inicio', 'fecha_fin')
    search_fields = ('codigo', 'nombre', 'descripcion')
    filter_horizontal = ('productos', 'categorias')
    ordering = ('-created_at',)
