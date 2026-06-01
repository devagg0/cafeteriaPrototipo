from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404

from ..views import JWTAuthentication, IsAuthenticatedJWT
from usuarios.models import Bitacora
from ..models import Pedido
from .serializers import HistorialPedidoSerializer, HistorialPedidoDetailSerializer
from .services import filtrar_pedidos
from usuarios.models import Usuario


class HistorialListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def get(self, request):
        qs = filtrar_pedidos(request.query_params, request.user)

        # Registrar en bitácora la consulta del historial
        try:
            Bitacora.objects.create(
                usuario=request.user,
                accion='consultar historial pedidos',
                detalles=f'Usuario={request.user.nombre} filtros={dict(request.query_params)}'
            )
        except Exception:
            # No fallar si la bitácora no puede guardarse
            pass

        if not qs.exists():
            return Response([], status=status.HTTP_200_OK)

        serializer = HistorialPedidoSerializer(qs, many=True, context={'request': request})
        return Response(serializer.data)


class HistorialDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def get(self, request, id):
        pedido = get_object_or_404(Pedido.objects.prefetch_related('detalles__producto'), id=id)

        # Permisos: cliente solo puede ver su propio pedido
        try:
            if request.user.cod_rol.cod_rol == 'cliente' and pedido.usuario != request.user:
                return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)
        except Exception:
            return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)

        # Registrar en bitácora la consulta del detalle
        try:
            Bitacora.objects.create(
                usuario=request.user,
                accion='consultar detalle pedido',
                detalles=f'Usuario={request.user.nombre} pedido_id={pedido.id}'
            )
        except Exception:
            pass

        serializer = HistorialPedidoDetailSerializer(pedido, context={'request': request})
        return Response(serializer.data)


class ClientesSugerenciasView(APIView):
    """Devuelve sugerencias de clientes para autocompletar (solo admin)."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def get(self, request):
        q = request.query_params.get('q', '').strip()

        # Permiso: solo admin puede usar esta ruta
        try:
            if not (request.user and request.user.cod_rol.cod_rol == 'admin'):
                return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)
        except Exception:
            return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)

        if not q:
            return Response([], status=status.HTTP_200_OK)

        # Buscar usuarios con rol cliente cuyo nombre coincida
        usuarios_qs = Usuario.objects.filter(cod_rol__cod_rol='cliente', nombre__icontains=q)[:10]
        results = [{'id': u.id_usuario, 'nombre': u.nombre} for u in usuarios_qs]
        return Response(results, status=status.HTTP_200_OK)
