from rest_framework import serializers
from .models import Categoria, Combo, ComboDetalle, Producto
from decimal import Decimal

class CategoriaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Categoria
        fields = '__all__'


class ProductoSerializer(serializers.ModelSerializer):
    categoria_nombre = serializers.ReadOnlyField(source='categoria.nombre')
    stock_disponible = serializers.SerializerMethodField()

    class Meta:
        model = Producto
        fields = '__all__'

    def get_stock_disponible(self, obj):
        return obj.stock - obj.stock_reservado


class ComboDetalleSerializer(serializers.ModelSerializer):
    producto_nombre = serializers.ReadOnlyField(source='producto.nombre')
    precio_unitario = serializers.ReadOnlyField(source='producto.precio')

    class Meta:
        model = ComboDetalle
        fields = ['id', 'producto', 'producto_nombre', 'precio_unitario', 'cantidad']


class ComboSerializer(serializers.ModelSerializer):
    detalles = ComboDetalleSerializer(many=True)
    precio_normal = serializers.SerializerMethodField()
    ahorro = serializers.SerializerMethodField()
    stock_disponible = serializers.SerializerMethodField()

    class Meta:
        model = Combo
        fields = [
            'id', 'nombre', 'descripcion', 'precio_especial', 'precio_normal',
            'ahorro', 'stock_disponible', 'estado', 'fecha_inicio', 'fecha_fin',
            'detalles', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_precio_normal(self, obj):
        return float(obj.precio_normal)

    def get_ahorro(self, obj):
        return float(max(obj.precio_normal - obj.precio_especial, 0))

    def get_stock_disponible(self, obj):
        return obj.stock_disponible

    def validate_detalles(self, value):
        if len(value) < 2:
            raise serializers.ValidationError('Un combo debe incluir al menos dos productos.')
        for item in value:
            if item.get('cantidad', 0) <= 0:
                raise serializers.ValidationError('La cantidad de cada producto debe ser mayor a 0.')
        return value

def create(self, validated_data):
    detalles = validated_data.pop('detalles', [])

    combo = Combo.objects.create(**validated_data)

    for detalle in detalles:
        ComboDetalle.objects.create(combo=combo, **detalle)

    # Calcular automáticamente el 15% de descuento
    combo.precio_especial = (
        combo.precio_normal * Decimal("0.85")
    ).quantize(Decimal("0.01"))

    combo.save(update_fields=["precio_especial"])

    return combo

    def update(self, instance, validated_data):
        detalles = validated_data.pop('detalles', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
    if detalles is not None:
     instance.detalles.all().delete()
    for detalle in detalles:
        ComboDetalle.objects.create(combo=instance, **detalle)

    instance.precio_especial = (
    instance.precio_normal * Decimal("0.85")
).quantize(Decimal("0.01"))

    instance.save(update_fields=["precio_especial"])

    return instance
