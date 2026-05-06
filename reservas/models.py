from django.db import models
from usuarios.models import Cliente

class SalaTematica(models.Model):
    ESTADOS_DISPONIBILIDAD = [
        ('disponible', 'Disponible'),
        ('no_disponible', 'No disponible'),
        ('mantenimiento', 'En mantenimiento'),
        ('reservada', 'Reservada'),
    ]

    nombre = models.CharField(max_length=100, unique=True)
    tematica = models.CharField(max_length=100, default='General')
    descripcion = models.TextField(blank=True, null=True)
    imagen_principal = models.ImageField(upload_to='salas/', blank=True, null=True)
    habilitada = models.BooleanField(default=True)
    capacidad_total = models.IntegerField(default=0)
    disponibilidad = models.CharField(max_length=20, choices=ESTADOS_DISPONIBILIDAD, default='disponible')
    fecha_creacion = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'sala'

    def __str__(self):
        return self.nombre

class SalaImagen(models.Model):
    sala = models.ForeignKey(SalaTematica, on_delete=models.CASCADE, related_name='galeria')
    imagen = models.ImageField(upload_to='salas/galeria/')
    fecha_subida = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'sala_imagen'


class Mesa(models.Model):
    ESTADOS_MESA = [
        ('disponible', 'Disponible'),
        ('ocupada', 'Ocupada'),
        ('reservada', 'Reservada'),
    ]
    sala = models.ForeignKey(SalaTematica, on_delete=models.CASCADE, related_name='mesas')
    nombre = models.CharField(max_length=50)
    capacidad = models.IntegerField(default=2)
    posicion_x = models.IntegerField(default=0)
    posicion_y = models.IntegerField(default=0)
    activa = models.BooleanField(default=True)
    estado = models.CharField(max_length=20, choices=ESTADOS_MESA, default='disponible')

    class Meta:
        db_table = 'mesa'

    def __str__(self):
        return f'{self.nombre} ({self.sala.nombre})'


class Reserva(models.Model):
    ESTADOS = [
        ('pendiente', 'Pendiente'),
        ('confirmada', 'Confirmada'),
        ('en_curso', 'En Curso'),
        ('finalizada', 'Finalizada'),
        ('cancelada', 'Cancelada'),
        ('liberada', 'Liberada'),
        ('no_asistio', 'No Asistió'),
    ]

    cliente = models.ForeignKey(Cliente, on_delete=models.CASCADE, related_name='reservas')
    sala = models.ForeignKey(SalaTematica, on_delete=models.CASCADE, related_name='reservas')
    mesa = models.ForeignKey(Mesa, on_delete=models.CASCADE, related_name='reservas')
    fecha = models.DateField()
    hora_inicio = models.TimeField()
    hora_fin = models.TimeField()
    cantidad_personas = models.IntegerField()
    estado = models.CharField(max_length=20, choices=ESTADOS, default='pendiente')
    creada_en = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'reserva'

    def __str__(self):
        return f'{self.cliente.id_usuario.nombre} - {self.mesa.nombre} ({self.fecha} {self.hora_inicio})'
