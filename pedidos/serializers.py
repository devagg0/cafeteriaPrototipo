from rest_framework import serializers
from producto.models import Categoria, Producto
from .models import Pedido, DetallePedido, Preorden, DetallePreorden

class DetallePedidoSerializer(serializers.ModelSerializer):
    producto_nombre    = serializers.ReadOnlyField(source='producto.nombre')
    producto_categoria = serializers.ReadOnlyField(source='producto.categoria.nombre')
    producto_imagen    = serializers.SerializerMethodField()
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
    total = serializers.SerializerMethodField()
    total_pendiente = serializers.SerializerMethodField()
    total_pagado = serializers.SerializerMethodField()
    cantidad_productos = serializers.SerializerMethodField()
    cantidad_pendientes = serializers.SerializerMethodField()
    cantidad_confirmados = serializers.SerializerMethodField()
    estado_mesa = serializers.SerializerMethodField()
    cliente_nombre = serializers.SerializerMethodField()
    cliente_id = serializers.ReadOnlyField(source='cliente.id_usuario.id_usuario')

    class Meta:
        model = Pedido
        fields = '__all__'

    def get_total(self, obj):
        return float(sum(d.subtotal for d in obj.detalles.all()))

    def get_total_pendiente(self, obj):
        from django.db.models import Sum
        from finanzas.models import Pago
        total_confirmado = sum(d.subtotal for d in obj.detalles.filter(confirmado=True))
        total_pagado = Pago.objects.filter(pedido=obj, estado='exitoso').aggregate(Sum('monto'))['monto__sum'] or 0.00
        return float(max(0.00, float(total_confirmado) - float(total_pagado)))

    def get_total_pagado(self, obj):
        from django.db.models import Sum
        from finanzas.models import Pago
        total_pagado = Pago.objects.filter(pedido=obj, estado='exitoso').aggregate(Sum('monto'))['monto__sum'] or 0.00
        return float(total_pagado)

    def get_cantidad_productos(self, obj):
        from django.db.models import Sum
        return obj.detalles.aggregate(total_qty=Sum('cantidad'))['total_qty'] or 0

    def get_cantidad_pendientes(self, obj):
        from django.db.models import Sum
        return obj.detalles.filter(confirmado=False).aggregate(total_qty=Sum('cantidad'))['total_qty'] or 0

    def get_cantidad_confirmados(self, obj):
        from django.db.models import Sum
        return obj.detalles.filter(confirmado=True).aggregate(total_qty=Sum('cantidad'))['total_qty'] or 0

    def get_estado_mesa(self, obj):
        if obj.mesa:
            if obj.mesa.estado == 'reservada':
                return 'RESERVADA'
            
            tiene_pendientes = obj.detalles.filter(confirmado=False).exists()
            total_confirmado = sum(d.subtotal for d in obj.detalles.filter(confirmado=True))
            from django.db.models import Sum
            from finanzas.models import Pago
            total_pagado = Pago.objects.filter(pedido=obj, estado='exitoso').aggregate(Sum('monto'))['monto__sum'] or 0.00
            total_pendiente = max(0.00, float(total_confirmado) - float(total_pagado))
            
            tiene_detalles = obj.detalles.exists()
            
            if tiene_detalles and (tiene_pendientes or total_pendiente > 0.00):
                return 'OCUPADA'
        return 'LIBRE'

    def get_cliente_nombre(self, obj):
        from .services import nombre_cliente_pedido
        return nombre_cliente_pedido(obj)

class CocinaDetallePedidoSerializer(serializers.ModelSerializer):
    producto_id = serializers.ReadOnlyField(source='producto.id')
    producto_nombre = serializers.ReadOnlyField(source='producto.nombre')

    class Meta:
        model = DetallePedido
        fields = [
            'id',
            'producto_id',
            'producto_nombre',
            'cantidad',
            'precio_unitario',
            'subtotal',
            'observaciones',
        ]

class CocinaComandaSerializer(serializers.ModelSerializer):
    id_pedido = serializers.IntegerField(source='id')
    origen = serializers.SerializerMethodField()
    cliente = serializers.SerializerMethodField()
    sala = serializers.SerializerMethodField()
    mesa = serializers.SerializerMethodField()
    fecha = serializers.SerializerMethodField()
    hora = serializers.SerializerMethodField()
    productos = CocinaDetallePedidoSerializer(source='detalles', many=True, read_only=True)
    observaciones = serializers.CharField(source='notas', read_only=True, allow_null=True)
    total = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)

    class Meta:
        model = Pedido
        fields = [
            'id_pedido',
            'origen',
            'cliente',
            'sala',
            'mesa',
            'fecha',
            'hora',
            'estado',
            'productos',
            'observaciones',
            'total',
        ]

    def get_origen(self, obj):
        return 'preorden' if obj.reserva else 'pedido_normal'

    def get_cliente(self, obj):
        if obj.reserva and obj.reserva.cliente and obj.reserva.cliente.id_usuario:
            return {
                'id': obj.reserva.cliente.id_usuario.id_usuario,
                'nombre': obj.reserva.cliente.id_usuario.nombre,
            }
        if obj.cliente and obj.cliente.id_usuario:
            return {
                'id': obj.cliente.id_usuario.id_usuario,
                'nombre': obj.cliente.id_usuario.nombre,
            }
        return {
            'id': None,
            'nombre': obj.nombre_cliente or 'Cliente presencial',
        }

    def get_sala(self, obj):
        if obj.sala:
            return obj.sala.nombre
        if obj.reserva and obj.reserva.sala:
            return obj.reserva.sala.nombre
        return None

    def get_mesa(self, obj):
        if obj.mesa:
            return obj.mesa.nombre
        if obj.reserva and obj.reserva.mesa:
            return obj.reserva.mesa.nombre
        return None

    def get_fecha(self, obj):
        if obj.reserva and obj.reserva.fecha:
            return obj.reserva.fecha
        return obj.created_at.date()

    def get_hora(self, obj):
        if obj.reserva and obj.reserva.hora_inicio:
            return obj.reserva.hora_inicio
        return obj.created_at.time()

class CocinaComandaDetailSerializer(CocinaComandaSerializer):
    fecha_creacion = serializers.DateTimeField(source='created_at', read_only=True)
    fecha_actualizacion = serializers.DateTimeField(source='updated_at', read_only=True)
    mesero_responsable = serializers.SerializerMethodField()

    class Meta(CocinaComandaSerializer.Meta):
        fields = CocinaComandaSerializer.Meta.fields + [
            'fecha_creacion',
            'fecha_actualizacion',
            'mesero_responsable',
        ]

    def get_mesero_responsable(self, obj):
        if obj.usuario and getattr(obj.usuario, 'cod_rol', None) and obj.usuario.cod_rol.cod_rol == 'mesero':
            return {
                'id': obj.usuario.id_usuario,
                'nombre': obj.usuario.nombre,
                'correo': obj.usuario.correo,
            }
        return None

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
