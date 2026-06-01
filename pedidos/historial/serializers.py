from rest_framework import serializers
from ..models import Pedido, DetallePedido


class HistorialPedidoSerializer(serializers.ModelSerializer):
    numero_pedido = serializers.SerializerMethodField()
    cliente = serializers.ReadOnlyField(source='usuario.nombre')
    fecha = serializers.SerializerMethodField()

    class Meta:
        model = Pedido
        fields = ('id', 'numero_pedido', 'cliente', 'fecha', 'estado', 'total')

    def get_numero_pedido(self, obj):
        return f'PED-{obj.id:03d}'

    def get_fecha(self, obj):
        return obj.created_at.date().isoformat()


class HistorialDetalleSerializer(serializers.ModelSerializer):
    producto = serializers.ReadOnlyField(source='producto.nombre')

    class Meta:
        model = DetallePedido
        fields = ('producto', 'cantidad', 'precio_unitario', 'subtotal')


class HistorialPedidoDetailSerializer(serializers.ModelSerializer):
    numero_pedido = serializers.SerializerMethodField()
    cliente = serializers.ReadOnlyField(source='usuario.nombre')
    fecha = serializers.SerializerMethodField()
    detalle = HistorialDetalleSerializer(source='detalles', many=True, read_only=True)

    class Meta:
        model = Pedido
        fields = ('id', 'numero_pedido', 'cliente', 'fecha', 'estado', 'total', 'detalle')

    def get_numero_pedido(self, obj):
        return f'PED-{obj.id:03d}'

    def get_fecha(self, obj):
        return obj.created_at.date().isoformat()
