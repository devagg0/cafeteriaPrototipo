from rest_framework import serializers

from .models import ConfiguracionPuntos, Cupon, CuponUso, Opinion, PuntoMovimiento


class OpinionSerializer(serializers.ModelSerializer):
    cliente_nombre = serializers.ReadOnlyField(source='usuario.nombre')
    cliente_correo = serializers.ReadOnlyField(source='usuario.correo')
    pedido_codigo = serializers.SerializerMethodField()

    class Meta:
        model = Opinion
        fields = [
            'id',
            'usuario',
            'cliente_nombre',
            'cliente_correo',
            'pedido',
            'pedido_codigo',
            'calificacion',
            'comentario',
            'fecha',
            'visible',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'usuario',
            'cliente_nombre',
            'cliente_correo',
            'fecha',
            'visible',
            'created_at',
            'updated_at',
        ]

    def get_pedido_codigo(self, obj):
        return f'PED-{obj.pedido_id:03d}' if obj.pedido_id else None

    def validate_calificacion(self, value):
        if value < 1 or value > 5:
            raise serializers.ValidationError('La calificación debe estar entre 1 y 5 estrellas.')
        return value

    def validate_comentario(self, value):
        texto = (value or '').strip()
        if len(texto) > 500:
            raise serializers.ValidationError('El comentario no puede superar los 500 caracteres.')
        return texto


class CuponSerializer(serializers.ModelSerializer):
    disponible = serializers.ReadOnlyField()

    class Meta:
        model = Cupon
        fields = '__all__'
        read_only_fields = ['usos_actuales', 'created_at', 'updated_at']

    def validate_codigo(self, value):
        return (value or '').strip().upper()

    def validate(self, attrs):
        tipo = attrs.get('tipo_descuento', getattr(self.instance, 'tipo_descuento', None))
        valor = attrs.get('valor_descuento', getattr(self.instance, 'valor_descuento', None))
        if valor is not None and valor <= 0:
            raise serializers.ValidationError({'valor_descuento': 'El descuento debe ser mayor a 0.'})
        if tipo == 'porcentaje' and valor and valor > 100:
            raise serializers.ValidationError({'valor_descuento': 'El porcentaje no puede ser mayor a 100.'})
        return attrs


class CuponUsoSerializer(serializers.ModelSerializer):
    codigo = serializers.ReadOnlyField(source='cupon.codigo')
    cliente = serializers.ReadOnlyField(source='usuario.nombre')

    class Meta:
        model = CuponUso
        fields = ['id', 'codigo', 'cliente', 'pedido', 'pago', 'monto_descuento', 'confirmado', 'created_at']


class ConfiguracionPuntosSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConfiguracionPuntos
        fields = '__all__'


class PuntoMovimientoSerializer(serializers.ModelSerializer):
    producto_nombre = serializers.ReadOnlyField(source='producto.nombre')
    pedido_codigo = serializers.SerializerMethodField()

    class Meta:
        model = PuntoMovimiento
        fields = ['id', 'tipo', 'puntos', 'saldo_resultante', 'pedido', 'pedido_codigo', 'producto', 'producto_nombre', 'descripcion', 'created_at']

    def get_pedido_codigo(self, obj):
        return f'PED-{obj.pedido_id:03d}' if obj.pedido_id else None
