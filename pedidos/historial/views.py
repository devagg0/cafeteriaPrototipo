from django.shortcuts import get_object_or_404
from django.db import transaction
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from ..models import DetallePedido, Pedido
from ..views import IsAuthenticatedJWT, JWTAuthentication
from .serializers import (
    HistorialPedidoDetailSerializer,
    HistorialPedidoSerializer,
    pedido_es_editable,
    reserva_relacionada_pedido,
)
from .services import filtrar_pedidos
from producto.models import Producto
from usuarios.models import Bitacora, Usuario


def registrar_bitacora_historial(request, total):
    try:
        qp = request.query_params
        page = qp.get('page') or '1'
        page_size = qp.get('page_size') or '10'

        filtros = []
        if qp.get('fecha'):
            filtros.append(f'fecha {qp.get("fecha")}')
        if qp.get('fecha_inicio'):
            filtros.append(f'desde {qp.get("fecha_inicio")}')
        if qp.get('fecha_fin'):
            filtros.append(f'hasta {qp.get("fecha_fin")}')
        if qp.get('estado'):
            filtros.append(f'resultado {qp.get("estado")}')
        if qp.get('cliente'):
            filtros.append(f'cliente {str(qp.get("cliente"))[:80]}')

        detalles = (
            f'Consulto el historial de pedidos. '
            f'Pagina {page}, {page_size} registros por pagina. '
            f'Resultados encontrados: {total}.'
        )
        if filtros:
            detalles += f' Filtros aplicados: {", ".join(filtros)}.'

            Bitacora.objects.create(
                usuario=request.user,
                accion='consultar historial pedidos',
                detalles=detalles,
            )
    except Exception:
        pass


class HistorialListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def get(self, request):
        es_cliente = getattr(getattr(request.user, 'cod_rol', None), 'cod_rol', None) == 'cliente'
        qs = filtrar_pedidos(request.query_params, None if es_cliente else request.user)
        pedidos_filtrados = None
        if es_cliente:
            pedidos_filtrados = [pedido for pedido in qs if pedido_pertenece_al_usuario(pedido, request.user)]

        try:
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 10))
            if page < 1:
                page = 1
            if page_size < 1:
                page_size = 10
        except Exception:
            page = 1
            page_size = 10

        total = len(pedidos_filtrados) if pedidos_filtrados is not None else qs.count()
        start = (page - 1) * page_size
        end = start + page_size
        qs_page = pedidos_filtrados[start:end] if pedidos_filtrados is not None else qs[start:end]

        registrar_bitacora_historial(request, total)

        if total == 0:
            return Response(
                {'results': [], 'count': 0, 'page': page, 'page_size': page_size},
                status=status.HTTP_200_OK,
            )

        serializer = HistorialPedidoSerializer(qs_page, many=True, context={'request': request})
        return Response({'results': serializer.data, 'count': total, 'page': page, 'page_size': page_size})


def pedido_pertenece_al_usuario(pedido, usuario):
    if pedido.usuario == usuario:
        return True
    if getattr(getattr(pedido, 'cliente', None), 'id_usuario', None) == usuario:
        return True
    reserva = reserva_relacionada_pedido(pedido)
    cliente_usuario = getattr(getattr(getattr(reserva, 'cliente', None), 'id_usuario', None), 'id_usuario', None)
    return cliente_usuario == getattr(usuario, 'id_usuario', None)


class PedidosActualesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def get(self, request):
        qs = filtrar_pedidos({}, None).filter(
            estado__in=['pendiente', 'confirmado', 'en_preparacion', 'lista']
        )
        pedidos = [pedido for pedido in qs if pedido_pertenece_al_usuario(pedido, request.user)]
        serializer = HistorialPedidoDetailSerializer(pedidos, many=True, context={'request': request})

        try:
            Bitacora.objects.create(
                usuario=request.user,
                accion='consultar pedidos actuales',
                detalles=f'Consulto sus pedidos actuales. Pedidos encontrados: {len(pedidos)}.',
            )
        except Exception:
            pass

        return Response({'results': serializer.data, 'count': len(pedidos)})


class PedidoEditarView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def patch(self, request, id):
        productos_req = request.data.get('productos', [])
        if not isinstance(productos_req, list) or not productos_req:
            return Response({'error': 'Debe incluir al menos un producto.'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            pedido = get_object_or_404(
                Pedido.objects.select_for_update().prefetch_related('detalles__producto'),
                id=id,
            )

            if not pedido_pertenece_al_usuario(pedido, request.user):
                return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)

            editable, motivo = pedido_es_editable(pedido)
            if not editable:
                return Response({'error': motivo}, status=status.HTTP_400_BAD_REQUEST)

            cantidades = {}
            for item in productos_req:
                try:
                    producto_id = int(item.get('id'))
                    cantidad = int(item.get('cantidad'))
                except Exception:
                    return Response({'error': 'Productos invalidos.'}, status=status.HTTP_400_BAD_REQUEST)
                if cantidad <= 0:
                    return Response({'error': 'Las cantidades deben ser mayores a 0.'}, status=status.HTTP_400_BAD_REQUEST)
                cantidades[producto_id] = cantidades.get(producto_id, 0) + cantidad

            detalles_actuales = list(pedido.detalles.select_related('producto').all())
            cantidad_anterior = {}
            for detalle in detalles_actuales:
                cantidad_anterior[detalle.producto_id] = cantidad_anterior.get(detalle.producto_id, 0) + detalle.cantidad

            productos = {
                p.id: p
                for p in Producto.objects.select_for_update().filter(id__in=cantidades.keys(), estado=True)
            }
            if len(productos) != len(cantidades):
                return Response({'error': 'Uno o mas productos no existen o no estan disponibles.'}, status=status.HTTP_400_BAD_REQUEST)

            for producto_id, cantidad in cantidades.items():
                producto = productos[producto_id]
                disponible = producto.stock + cantidad_anterior.get(producto_id, 0)
                if cantidad > disponible:
                    return Response(
                        {'error': f'Stock insuficiente para "{producto.nombre}". Disponible: {disponible}.'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            for detalle in detalles_actuales:
                producto = detalle.producto
                producto.stock += detalle.cantidad
                producto.save()
            pedido.detalles.all().delete()

            total = 0
            for producto_id, cantidad in cantidades.items():
                producto = productos[producto_id]
                subtotal = producto.precio * cantidad
                DetallePedido.objects.create(
                    pedido=pedido,
                    producto=producto,
                    cantidad=cantidad,
                    precio_unitario=producto.precio,
                    subtotal=subtotal,
                )
                producto.stock -= cantidad
                producto.save()
                total += subtotal

            pedido.total = total
            pedido.save()

        try:
            Bitacora.objects.create(
                usuario=request.user,
                accion='editar pedido actual',
                detalles=f'Actualizo productos del pedido PED-{pedido.id:03d}. Total: Bs. {pedido.total}.',
            )
        except Exception:
            pass

        pedido = Pedido.objects.prefetch_related('detalles__producto').get(id=pedido.id)
        serializer = HistorialPedidoDetailSerializer(pedido, context={'request': request})
        return Response({'mensaje': 'Pedido actualizado correctamente.', 'pedido': serializer.data})


class HistorialDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def get(self, request, id):
        pedido = get_object_or_404(
            Pedido.objects.select_related(
                'usuario',
                'usuario__cod_rol',
                'cliente__id_usuario',
                'reserva__cliente__id_usuario',
                'reserva__sala',
                'reserva__mesa',
                'sala',
                'mesa',
            ).prefetch_related('detalles__producto', 'reserva__preordenes__usuario_mesero__cod_rol'),
            id=id,
        )

        try:
            cliente_reserva = getattr(getattr(getattr(pedido, 'reserva', None), 'cliente', None), 'id_usuario', None)
            cliente_directo = getattr(getattr(pedido, 'cliente', None), 'id_usuario', None)
            es_cliente = request.user.cod_rol.cod_rol == 'cliente'
            if (
                es_cliente
                and pedido.usuario != request.user
                and cliente_reserva != request.user
                and cliente_directo != request.user
            ):
                return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)
        except Exception:
            return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)

        try:
            Bitacora.objects.create(
                usuario=request.user,
                accion='consultar detalle pedido',
                detalles=f'Consulto el detalle del pedido PED-{pedido.id:03d}.',
            )
        except Exception:
            pass

        serializer = HistorialPedidoDetailSerializer(pedido, context={'request': request})
        return Response(serializer.data)


class ClientesSugerenciasView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def get(self, request):
        q = request.query_params.get('q', '').strip()

        try:
            if not (request.user and request.user.cod_rol.cod_rol == 'admin'):
                return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)
        except Exception:
            return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)

        if not q:
            return Response([], status=status.HTTP_200_OK)

        usuarios_qs = Usuario.objects.filter(cod_rol__cod_rol='cliente', nombre__icontains=q)[:10]
        results = [{'id': u.id_usuario, 'nombre': u.nombre} for u in usuarios_qs]
        return Response(results, status=status.HTTP_200_OK)
