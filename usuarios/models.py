from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_migrate
from django.dispatch import receiver


class Rol(models.Model):
    cod_rol = models.BigAutoField(primary_key=True)
    nombre = models.CharField(max_length=30, unique=True)
    descripcion = models.TextField(blank=True)

    class Meta:
        verbose_name = 'Rol'
        verbose_name_plural = 'Roles'

    def __str__(self):
        return self.nombre


class PerfilUsuario(models.Model):
    usuario = models.OneToOneField(User, on_delete=models.CASCADE, related_name='perfil')
    rol = models.ForeignKey(Rol, on_delete=models.PROTECT, related_name='perfiles')
    telefono = models.CharField(max_length=30, blank=True)
    direccion = models.CharField(max_length=200, blank=True)
    creado_el = models.DateTimeField(auto_now_add=True)
    actualizado_el = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.usuario.username} - perfil'


class Empleado(models.Model):
    cod_empleado = models.BigAutoField(primary_key=True)
    usuario = models.OneToOneField(User, on_delete=models.CASCADE, related_name='empleado_perfil')
    cargo = models.CharField(max_length=50)
    turno = models.CharField(max_length=50)
    fecha_contratacion = models.DateField(blank=True, null=True)
    notas = models.TextField(blank=True)

    def __str__(self):
        return f'{self.usuario.username} - {self.cargo} ({self.turno})'


class Cliente(models.Model):
    cod_cliente = models.BigAutoField(primary_key=True)
    usuario = models.OneToOneField(User, on_delete=models.CASCADE, related_name='cliente_perfil')
    correo_contacto = models.EmailField(blank=True)
    puntos_fidelidad = models.IntegerField(default=0)
    notas = models.TextField(blank=True)

    def __str__(self):
        return f'{self.usuario.username} - cliente'


@receiver(post_migrate)
def crear_roles_por_defecto(sender, **kwargs):
    if sender.name != 'usuarios':
        return

    roles = [
        ('Admin', 'Administrador con acceso completo'),
        ('Empleado', 'Usuario con permisos de empleado'),
        ('Cliente', 'Usuario con permisos de cliente'),
    ]
    for nombre, descripcion in roles:
        Rol.objects.get_or_create(nombre=nombre, defaults={'descripcion': descripcion})
