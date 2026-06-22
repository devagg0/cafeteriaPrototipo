from django.contrib import admin

from .models import Promocion


@admin.register(Promocion)
class PromocionAdmin(admin.ModelAdmin):
    list_display = (
        'codigo',
        'nombre',
        'tipo_descuento',
        'valor_descuento',
        'fecha_inicio',
        'fecha_fin',
        'activa',
    )
    list_filter = ('activa', 'tipo_descuento')
    search_fields = ('codigo', 'nombre', 'descripcion')
    filter_horizontal = ('productos', 'categorias')
