from django.contrib import admin
from .models import Rol, PerfilUsuario, Empleado, Cliente


@admin.register(Rol)
class RolAdmin(admin.ModelAdmin):
    list_display = ('cod_rol', 'nombre', 'descripcion')
    search_fields = ('nombre',)


@admin.register(PerfilUsuario)
class PerfilUsuarioAdmin(admin.ModelAdmin):
    list_display = ('usuario', 'rol', 'telefono', 'direccion', 'creado_el')
    search_fields = ('usuario__username', 'usuario__email')
    list_filter = ('rol', 'creado_el')


@admin.register(Empleado)
class EmpleadoAdmin(admin.ModelAdmin):
    list_display = ('cod_empleado', 'usuario', 'cargo', 'turno', 'fecha_contratacion')
    search_fields = ('usuario__username', 'cargo')
    list_filter = ('turno', 'fecha_contratacion')


@admin.register(Cliente)
class ClienteAdmin(admin.ModelAdmin):
    list_display = ('cod_cliente', 'usuario', 'correo_contacto', 'puntos_fidelidad')
    search_fields = ('usuario__username', 'correo_contacto')
    list_filter = ('puntos_fidelidad',)
