from django.db import models
from django.db.models.signals import post_migrate
from django.dispatch import receiver


class Rol(models.Model):
    cod_rol = models.CharField(max_length=10, primary_key=True)
    nombre = models.CharField(max_length=20)
    descripcion = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.nombre


class Usuario(models.Model):
    id_usuario = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=50)
    correo = models.EmailField(max_length=60, unique=True)
    contrasena = models.CharField(max_length=100)
    cod_rol = models.ForeignKey(Rol, on_delete=models.CASCADE, related_name='usuarios')

    codigo_recuperacion = models.CharField(max_length=6, null=True, blank=True)

    def __str__(self):
        return self.nombre


class Cliente(models.Model):
    cod_cliente = models.CharField(max_length=6, primary_key=True)
    telefono = models.CharField(max_length=15, null=True, blank=True)  # ✔ permite null
    direccion = models.CharField(max_length=100)
    id_usuario = models.OneToOneField(
    Usuario,
    on_delete=models.CASCADE,
    related_name='cliente',
    db_column='id_usuario'
)
    def __str__(self):
        return f'{self.cod_cliente} - {self.id_usuario.nombre}'


class Empleado(models.Model):
    cod_empleado = models.CharField(max_length=6, primary_key=True)
    cargo = models.CharField(max_length=30)
    turno = models.CharField(max_length=20)
    id_usuario = models.OneToOneField(Usuario, on_delete=models.CASCADE, related_name='empleado')

    def __str__(self):
        return f'{self.cod_empleado} - {self.id_usuario.nombre}'


class Bitacora(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name='bitacoras')
    accion = models.CharField(max_length=100)
    detalles = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'{self.usuario.nombre} - {self.accion}'


@receiver(post_migrate)
def crear_roles_por_defecto(sender, **kwargs):
    if sender.name != 'usuarios':
        return

    roles = [
        ('admin', 'Admin', 'Administrador'),
        ('mesero', 'Mesero', 'Servicio'),
        ('cocinero', 'Cocinero', 'Cocina'),
        ('cliente', 'Cliente', 'Cliente'),
        ('emp', 'Empleado', 'Empleado general'),  # 🔥 IMPORTANTE
    ]

    for cod, nombre, descripcion in roles:
        Rol.objects.get_or_create(
            cod_rol=cod,
            defaults={'nombre': nombre, 'descripcion': descripcion}
        )