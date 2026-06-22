from rest_framework import serializers
from .models import Promocion
from producto.models import Producto, Categoria

class PromocionSerializer(serializers.ModelSerializer):
    # Campos adicionales de solo lectura para exponer nombres asociados
    nombres_productos = serializers.SerializerMethodField(read_only=True)
    nombres_categorias = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Promocion
        fields = [
            'id',
            'codigo',
            'nombre',
            'descripcion',
            'tipo_descuento',
            'valor_descuento',
            'fecha_inicio',
            'fecha_fin',
            'activa',
            'productos',
            'categorias',
            'nombres_productos',
            'nombres_categorias',
            'created_at',
            'updated_at',
        ]

    def get_nombres_productos(self, obj):
        # Retorna la lista de nombres de productos asociados
        return [p.nombre for p in obj.productos.all()]

    def get_nombres_categorias(self, obj):
        # Retorna la lista de nombres de categorías asociadas
        return [c.nombre for c in obj.categorias.all()]

    def validate(self, data):
        # Realizar validaciones de negocio en el serializador para devolver errores API limpios
        instance = self.instance
        tipo_descuento = data.get('tipo_descuento', instance.tipo_descuento if instance else None)
        valor_descuento = data.get('valor_descuento', instance.valor_descuento if instance else None)
        fecha_inicio = data.get('fecha_inicio', instance.fecha_inicio if instance else None)
        fecha_fin = data.get('fecha_fin', instance.fecha_fin if instance else None)

        if valor_descuento is not None and valor_descuento <= 0:
            raise serializers.ValidationError({
                'valor_descuento': 'El valor del descuento debe ser mayor a 0.'
            })

        if tipo_descuento == 'porcentaje' and valor_descuento is not None and valor_descuento > 100:
            raise serializers.ValidationError({
                'valor_descuento': 'El porcentaje de descuento no puede ser mayor a 100%.'
            })

        if fecha_inicio and fecha_fin and fecha_fin < fecha_inicio:
            raise serializers.ValidationError({
                'fecha_fin': 'La fecha de fin no puede ser anterior a la fecha de inicio.'
            })

        return data
