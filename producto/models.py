from django.db import models

class Categoria(models.Model):
    nombre = models.CharField(max_length=100, unique=True)
    descripcion = models.TextField(blank=True, null=True)
    estado = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'categoria'

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

    @property
    def stock_disponible(self):
        return self.stock - self.stock_reservado

    def __str__(self):
        return self.nombre


class Combo(models.Model):
    nombre = models.CharField(max_length=150)
    descripcion = models.TextField(blank=True, null=True)
    precio_especial = models.DecimalField(max_digits=10, decimal_places=2)
    estado = models.BooleanField(default=True)
    fecha_inicio = models.DateField(blank=True, null=True)
    fecha_fin = models.DateField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'combo'

    @property
    def precio_normal(self):
        return sum(det.producto.precio * det.cantidad for det in self.detalles.select_related('producto'))

    @property
    def stock_disponible(self):
        cantidades = [
            det.producto.stock_disponible // det.cantidad
            for det in self.detalles.select_related('producto')
            if det.cantidad > 0
        ]
        return min(cantidades) if cantidades else 0

    def __str__(self):
        return self.nombre


class ComboDetalle(models.Model):
    combo = models.ForeignKey(Combo, on_delete=models.CASCADE, related_name='detalles')
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE, related_name='combo_detalles')
    cantidad = models.PositiveIntegerField(default=1)

    class Meta:
        db_table = 'combo_detalle'
        unique_together = ('combo', 'producto')

    def __str__(self):
        return f'{self.combo.nombre} - {self.producto.nombre}'
