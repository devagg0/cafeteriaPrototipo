from django.db import models
from django.db.models import Q
from django.utils import timezone
from reservas.models import Reserva
from pedidos.models import Pedido, Preorden

class Opinion(models.Model):
    usuario = models.ForeignKey(
        'usuarios.Usuario',
        on_delete=models.CASCADE,
        related_name='opiniones',
    )
    pedido = models.ForeignKey(
        'pedidos.Pedido',
        on_delete=models.SET_NULL,
        related_name='opiniones',
        null=True,
        blank=True,
    )
    calificacion = models.PositiveSmallIntegerField()
    comentario = models.CharField(max_length=500, blank=True)
    fecha = models.DateField(default=timezone.localdate)
    visible = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'opinion'
        ordering = ['-created_at']
        constraints = [
            models.CheckConstraint(
                check=Q(calificacion__gte=1) & Q(calificacion__lte=5),
                name='opinion_calificacion_1_5',
            ),
            models.UniqueConstraint(
                fields=['usuario', 'fecha'],
                name='opinion_unica_usuario_fecha',
            ),
        ]

    def __str__(self):
        return f'{self.usuario.nombre} - {self.calificacion} estrellas'

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
    caja_cerrada = models.BooleanField(default=False)
    caja_cerrada_en = models.DateTimeField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'pago'
        app_label = 'finanzas'

    def __str__(self):
        return f'Pago {self.id} - {self.metodo_pago} ({self.estado}) - Bs {self.monto}'
