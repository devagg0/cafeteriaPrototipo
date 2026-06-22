from django.db import models
from usuarios.models import Cliente
from producto.models import Categoria, Producto

class Pedido(models.Model):
    ESTADOS_PEDIDO = [
        ('pendiente', 'Pendiente'),
        ('confirmado', 'Confirmado'),
        ('en_preparacion', 'En preparación'),
        ('lista', 'Lista'),
        ('entregada', 'Entregada'),
        ('cancelado', 'Cancelado'),
    ]
    reserva = models.OneToOneField('reservas.Reserva', on_delete=models.CASCADE, related_name='pedido', null=True, blank=True)
    sala = models.ForeignKey('reservas.SalaTematica', on_delete=models.SET_NULL, null=True, blank=True, related_name='pedidos_directos')
    mesa = models.ForeignKey('reservas.Mesa', on_delete=models.SET_NULL, null=True, blank=True, related_name='pedidos_directos')
    usuario = models.ForeignKey('usuarios.Usuario', on_delete=models.CASCADE, related_name='pedidos')
    cliente = models.ForeignKey(
        'usuarios.Cliente',
        on_delete=models.SET_NULL,
        related_name='pedidos_presenciales',
        null=True,
        blank=True,
    )
    nombre_cliente = models.CharField(max_length=100, default='Cliente presencial')
    promocion = models.ForeignKey(
        'promocion.Promocion',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='pedidos'
    )
    descuento = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    notas = models.TextField(blank=True, null=True)
    estado = models.CharField(max_length=20, choices=ESTADOS_PEDIDO, default='pendiente')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        db_table = 'pedido'
        app_label = 'pedidos'
    def __str__(self):
        if self.reserva:
            return f'Pedido {self.id} - Reserva {self.reserva.id}'
        return f'Pedido {self.id} - Mesa {self.mesa}'

class DetallePedido(models.Model):
    pedido = models.ForeignKey(Pedido, on_delete=models.CASCADE, related_name='detalles')
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE)
    cantidad = models.IntegerField()
    precio_unitario = models.DecimalField(max_digits=10, decimal_places=2)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)
    observaciones = models.TextField(blank=True, null=True)
    confirmado = models.BooleanField(default=False)
    fecha_confirmacion = models.DateTimeField(null=True, blank=True)
    usuario_confirmacion = models.ForeignKey('usuarios.Usuario', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        db_table = 'detalle_pedido'
        app_label = 'pedidos'
    def __str__(self):
        return f'Detalle {self.id} - Producto {self.producto.nombre}'

class Notificacion(models.Model):
    TIPOS = [
        ('nuevo_pedido', 'Nuevo pedido'),
        ('pedido_listo', 'Pedido listo'),
    ]
    usuario_destino = models.ForeignKey(
        'usuarios.Usuario',
        on_delete=models.CASCADE,
        related_name='notificaciones',
    )
    pedido = models.ForeignKey(
        Pedido,
        on_delete=models.CASCADE,
        related_name='notificaciones',
        null=True,
        blank=True,
    )
    titulo = models.CharField(max_length=100)
    mensaje = models.TextField()
    tipo = models.CharField(max_length=30, choices=TIPOS)
    leido = models.BooleanField(default=False)
    fecha_creacion = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'notificacion'
        app_label = 'pedidos'
        constraints = [
            models.UniqueConstraint(
                fields=['usuario_destino', 'pedido', 'tipo'],
                name='notificacion_operativa_unica',
            ),
        ]

    def __str__(self):
        return f'{self.titulo} - {self.usuario_destino.nombre}'

class Preorden(models.Model):
    ESTADOS = [
        ('programada', 'Programada'),
        ('apartada', 'Apartada'),
        ('con_pedido', 'Con Pedido'),
        ('sin_stock', 'Sin Stock'),
        ('cancelada', 'Cancelada'),
        ('entregada', 'Entregada'),
    ]
    reserva = models.ForeignKey('reservas.Reserva', on_delete=models.SET_NULL, null=True, blank=True, related_name='preordenes')
    cliente = models.ForeignKey('usuarios.Cliente', on_delete=models.SET_NULL, null=True, blank=True, related_name='preordenes')
    sala = models.ForeignKey('reservas.SalaTematica', on_delete=models.SET_NULL, null=True, blank=True, related_name='preordenes')
    mesa = models.ForeignKey('reservas.Mesa', on_delete=models.SET_NULL, null=True, blank=True, related_name='preordenes')
    usuario_mesero = models.ForeignKey('usuarios.Usuario', on_delete=models.SET_NULL, null=True, blank=True, related_name='preordenes_gestionadas')
    estado = models.CharField(max_length=20, choices=ESTADOS, default='programada')
    notas = models.TextField(blank=True, null=True)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        db_table = 'preorden'
        app_label = 'pedidos'
    def __str__(self):
        cliente_nombre = self.cliente.id_usuario.nombre if self.cliente else 'Sin cliente'
        return f'Preorden {self.id} - {cliente_nombre} ({self.estado})'

class DetallePreorden(models.Model):
    preorden = models.ForeignKey(Preorden, on_delete=models.CASCADE, related_name='detalles')
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE)
    cantidad = models.IntegerField()
    precio_unitario = models.DecimalField(max_digits=10, decimal_places=2)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        db_table = 'detalle_preorden'
        app_label = 'pedidos'
    def __str__(self):
        return f'DetallePreorden {self.id} - {self.producto.nombre}'
