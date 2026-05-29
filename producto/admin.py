from django.contrib import admin
from .models import Categoria, Producto

@admin.register(Categoria)
class CategoriaAdmin(admin.ModelAdmin):
    list_display = ('id', 'nombre', 'estado', 'created_at', 'updated_at')
    list_filter = ('estado',)
    search_fields = ('nombre', 'descripcion')
    ordering = ('nombre',)


@admin.register(Producto)
class ProductoAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'nombre', 'categoria', 'precio', 'stock', 
        'stock_reservado', 'stock_disponible_display', 'estado', 'created_at'
    )
    list_filter = ('estado', 'categoria')
    search_fields = ('nombre', 'descripcion')
    readonly_fields = ('stock_reservado', 'stock_disponible_display')
    ordering = ('nombre',)

    def stock_disponible_display(self, obj):
        return obj.stock_disponible
    stock_disponible_display.short_description = 'Stock Disponible'
