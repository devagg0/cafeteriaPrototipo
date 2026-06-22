from django.db import models
from django.core.exceptions import ValidationError
from producto.models import Producto, Categoria

class Promocion(models.Model):
    TIPO_DESCUENTO_CHOICES = [
        ('porcentaje', 'Porcentaje'),
        ('monto_fijo', 'Monto Fijo'),
    ]

    codigo = models.CharField(max_length=30, unique=True)
    nombre = models.CharField(max_length=100)
    descripcion = models.TextField(blank=True, null=True)
    tipo_descuento = models.CharField(max_length=15, choices=TIPO_DESCUENTO_CHOICES)
    valor_descuento = models.DecimalField(max_digits=10, decimal_places=2)
    fecha_inicio = models.DateField()
    fecha_fin = models.DateField()
    activa = models.BooleanField(default=True)
    productos = models.ManyToManyField(Producto, blank=True, related_name='promociones')
    categorias = models.ManyToManyField(Categoria, blank=True, related_name='promociones')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'promocion'
        ordering = ['-created_at']

    def clean(self):
        super().clean()
        
        # Validar que el valor del descuento sea mayor a 0
        if self.valor_descuento is not None and self.valor_descuento <= 0:
            raise ValidationError({
                'valor_descuento': 'El valor del descuento debe ser mayor a 0.'
            })
        
        # Validar que el porcentaje de descuento no exceda 100%
        if self.tipo_descuento == 'porcentaje' and self.valor_descuento is not None and self.valor_descuento > 100:
            raise ValidationError({
                'valor_descuento': 'El porcentaje de descuento no puede ser mayor a 100%.'
            })
        
        # Validar que la fecha de fin no sea anterior a la fecha de inicio
        if self.fecha_inicio and self.fecha_fin and self.fecha_fin < self.fecha_inicio:
            raise ValidationError({
                'fecha_fin': 'La fecha de fin no puede ser anterior a la fecha de inicio.'
            })

    def save(self, *args, **kwargs):
        # Guardar el código siempre en mayúsculas
        if self.codigo:
            self.codigo = self.codigo.upper()
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.codigo} - {self.nombre}"
