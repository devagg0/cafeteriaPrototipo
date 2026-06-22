from rest_framework import serializers

from .models import Promocion


class PromocionSerializer(serializers.ModelSerializer):
    nombres_productos = serializers.SerializerMethodField()
    nombres_categorias = serializers.SerializerMethodField()

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
        return [producto.nombre for producto in obj.productos.all()]

    def get_nombres_categorias(self, obj):
        return [categoria.nombre for categoria in obj.categorias.all()]

    def validate_codigo(self, value):
        codigo = value.strip().upper()
        existentes = Promocion.objects.filter(codigo__iexact=codigo)
        if self.instance:
            existentes = existentes.exclude(pk=self.instance.pk)
        if existentes.exists():
            raise serializers.ValidationError('Ya existe una promoción con este código.')
        return codigo

    def validate(self, attrs):
        instance = self.instance
        tipo = attrs.get('tipo_descuento', getattr(instance, 'tipo_descuento', None))
        valor = attrs.get('valor_descuento', getattr(instance, 'valor_descuento', None))
        inicio = attrs.get('fecha_inicio', getattr(instance, 'fecha_inicio', None))
        fin = attrs.get('fecha_fin', getattr(instance, 'fecha_fin', None))

        if valor is not None and valor <= 0:
            raise serializers.ValidationError({
                'valor_descuento': 'El valor del descuento debe ser mayor a 0.',
            })
        if tipo == 'porcentaje' and valor is not None and valor > 100:
            raise serializers.ValidationError({
                'valor_descuento': 'El porcentaje de descuento no puede ser mayor a 100%.',
            })
        if inicio and fin and fin < inicio:
            raise serializers.ValidationError({
                'fecha_fin': 'La fecha de fin no puede ser anterior a la fecha de inicio.',
            })
        return attrs
