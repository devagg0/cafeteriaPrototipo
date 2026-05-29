from django.db import models
from usuarios.models import Cliente

class Categoria(models.Model):
    nombre = models.CharField(max_length=100, unique=True)
    descripcion = models.TextField(blank=True, null=True)
    estado = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        db_table = 'categoria'
        app_label = 'pedidos'
    def __str__(self):
        return self.nombre

class Producto(models.Model):
    categoria = models.ForeignKey(Categoria, on_delete=models.CASCADE, related_name='productos')
    nombre = models.CharField(max_length=150)
    descripcion = models.TextField(blank=True, null=True)
    precio = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.IntegerField(default=0)
    stock_reservado = models.IntegerField(default=0)
    imagen = models.ImageField(upload_to='productos/', blank=True, null=True)
    estado = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        db_table = 'producto'
        app_label = 'pedidos'
    @property
    def stock_disponible(self):
        return self.stock - self.stock_reservado
    def __str__(self):
        return self.nombre

class Pedido(models.Model):
    ESTADOS_PEDIDO = [
        ('pendiente', 'Pendiente'),
        ('confirmado', 'Confirmado'),
        ('cancelado', 'Cancelado'),
    ]
    reserva = models.OneToOneField('reservas.Reserva', on_delete=models.CASCADE, related_name='pedido', null=True, blank=True)
    sala = models.ForeignKey('reservas.SalaTematica', on_delete=models.SET_NULL, null=True, blank=True, related_name='pedidos_directos')
    mesa = models.ForeignKey('reservas.Mesa', on_delete=models.SET_NULL, null=True, blank=True, related_name='pedidos_directos')
    usuario = models.ForeignKey('usuarios.Usuario', on_delete=models.CASCADE, related_name='pedidos')
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        db_table = 'detalle_pedido'
        app_label = 'pedidos'
    def __str__(self):
        return f'Detalle {self.id} - Producto {self.producto.nombre}'

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
