from rest_framework import serializers
from producto.models import Categoria, Producto
from .models import Pedido, DetallePedido, Preorden, DetallePreorden

class DetallePedidoSerializer(serializers.ModelSerializer):
    producto_nombre = serializers.ReadOnlyField(source='producto.nombre')
    producto_imagen = serializers.SerializerMethodField()
    class Meta:
        model = DetallePedido
        fields = '__all__'
        read_only_fields = ['pedido', 'precio_unitario', 'subtotal']
    def get_producto_imagen(self, obj):
        if obj.producto.imagen:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.producto.imagen.url)
            return obj.producto.imagen.url
        return None

class PedidoSerializer(serializers.ModelSerializer):
    detalles = DetallePedidoSerializer(many=True, read_only=True)
    reserva_id = serializers.PrimaryKeyRelatedField(source='reserva', read_only=True)
    sala_nombre = serializers.ReadOnlyField(source='sala.nombre')
    mesa_nombre = serializers.ReadOnlyField(source='mesa.nombre')
    class Meta:
        model = Pedido
        fields = '__all__'

class DetallePreordenSerializer(serializers.ModelSerializer):
    producto_nombre = serializers.ReadOnlyField(source='producto.nombre')
    producto_categoria = serializers.ReadOnlyField(source='producto.categoria.nombre')
    producto_imagen = serializers.SerializerMethodField()
    class Meta:
        model = DetallePreorden
        fields = '__all__'
    def get_producto_imagen(self, obj):
        if obj.producto.imagen:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.producto.imagen.url)
            return obj.producto.imagen.url
        return None

class PreordenSerializer(serializers.ModelSerializer):
    detalles = DetallePreordenSerializer(many=True, read_only=True)
    sala_nombre = serializers.ReadOnlyField(source='sala.nombre')
    mesa_nombre = serializers.ReadOnlyField(source='mesa.nombre')
    mesero_nombre = serializers.ReadOnlyField(source='usuario_mesero.nombre')
    cliente_nombre = serializers.SerializerMethodField()
    reserva_fecha = serializers.ReadOnlyField(source='reserva.fecha')
    reserva_hora_inicio = serializers.ReadOnlyField(source='reserva.hora_inicio')
    reserva_hora_fin = serializers.ReadOnlyField(source='reserva.hora_fin')
    class Meta:
        model = Preorden
        fields = '__all__'
    def get_cliente_nombre(self, obj):
        if obj.cliente and obj.cliente.id_usuario:
            return obj.cliente.id_usuario.nombre
        return None
