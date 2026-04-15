from django.contrib import admin
from .models import Rol, Usuario, Empleado, Cliente


@admin.register(Rol)
class RolAdmin(admin.ModelAdmin):
    list_display = ('cod_rol', 'nombre', 'descripcion')
    search_fields = ('nombre',)


@admin.register(Usuario)
class UsuarioAdmin(admin.ModelAdmin):
    list_display = ('id_usuario', 'nombre', 'correo', 'cod_rol')
    search_fields = ('nombre', 'correo')
    list_filter = ('cod_rol',)


@admin.register(Empleado)
class EmpleadoAdmin(admin.ModelAdmin):
    list_display = ('cod_empleado', 'id_usuario', 'cargo', 'turno')
    search_fields = ('id_usuario__nombre', 'cargo')
    list_filter = ('turno',)


@admin.register(Cliente)
class ClienteAdmin(admin.ModelAdmin):
    list_display = ('cod_cliente', 'id_usuario', 'telefono')
    search_fields = ('id_usuario__nombre', 'telefono')

