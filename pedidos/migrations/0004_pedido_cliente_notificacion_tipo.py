import django.db.models.deletion
from django.db import migrations, models


def completar_tipos_notificacion(apps, schema_editor):
    Notificacion = apps.get_model('pedidos', 'Notificacion')
    Notificacion.objects.filter(tipo='').update(tipo='pedido_listo')


class Migration(migrations.Migration):
    dependencies = [
        ('pedidos', '0003_detallepedido_confirmado_and_more'),
        ('usuarios', '0009_usuario_foto_perfil'),
    ]

    operations = [
        migrations.AddField(
            model_name='pedido',
            name='cliente',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='pedidos_presenciales',
                to='usuarios.cliente',
            ),
        ),
        migrations.AddField(
            model_name='pedido',
            name='nombre_cliente',
            field=models.CharField(default='Cliente presencial', max_length=100),
        ),
        migrations.AddField(
            model_name='notificacion',
            name='tipo',
            field=models.CharField(default='', max_length=30),
            preserve_default=False,
        ),
        migrations.RunPython(completar_tipos_notificacion, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='notificacion',
            name='tipo',
            field=models.CharField(
                choices=[('nuevo_pedido', 'Nuevo pedido'), ('pedido_listo', 'Pedido listo')],
                max_length=30,
            ),
        ),
        migrations.AddConstraint(
            model_name='notificacion',
            constraint=models.UniqueConstraint(
                fields=('usuario_destino', 'pedido', 'tipo'),
                name='notificacion_operativa_unica',
            ),
        ),
    ]
