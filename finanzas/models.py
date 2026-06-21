from django.db import models
from reservas.models import Reserva
from pedidos.models import Pedido, Preorden

class Pago(models.Model):
    METODO_PAGO_CHOICES = [
        ('stripe', 'Stripe'),
        ('qr', 'Código QR'),
        ('efectivo', 'Efectivo'),
    ]
    
    ESTADO_PAGO_CHOICES = [
        ('pendiente', 'Pendiente'),
        ('exitoso', 'Exitoso'),
        ('cancelado', 'Cancelado'),
        ('fallido', 'Fallido'),
    ]
    
    reserva = models.ForeignKey(Reserva, on_delete=models.SET_NULL, null=True, blank=True, related_name='pagos')
    pedido = models.ForeignKey(Pedido, on_delete=models.SET_NULL, null=True, blank=True, related_name='pagos')
    preorden = models.ForeignKey(Preorden, on_delete=models.SET_NULL, null=True, blank=True, related_name='pagos')
    
    monto = models.DecimalField(max_digits=10, decimal_places=2)
    metodo_pago = models.CharField(max_length=20, choices=METODO_PAGO_CHOICES)
    estado = models.CharField(max_length=20, choices=ESTADO_PAGO_CHOICES, default='pendiente')
    
    stripe_session_id = models.CharField(max_length=255, blank=True, null=True)
    stripe_payment_intent = models.CharField(max_length=255, blank=True, null=True)
    usuario = models.ForeignKey('usuarios.Usuario', on_delete=models.SET_NULL, null=True, blank=True, related_name='pagos_procesados')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'pago'
        app_label = 'finanzas'

    def __str__(self):
        return f'Pago {self.id} - {self.metodo_pago} ({self.estado}) - Bs {self.monto}'
