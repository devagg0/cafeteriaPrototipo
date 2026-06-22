import django.db.models.deletion
from django.db import migrations, models


def agregar_campos_si_faltan(apps, schema_editor):
    Pedido = apps.get_model('pedidos', 'Pedido')
    Promocion = apps.get_model('promocion', 'Promocion')
    tabla = Pedido._meta.db_table
    with schema_editor.connection.cursor() as cursor:
        columnas = {
            columna.name
            for columna in schema_editor.connection.introspection.get_table_description(
                cursor,
                tabla,
            )
        }

    if 'descuento' not in columnas:
        campo_descuento = models.DecimalField(
            decimal_places=2,
            default=0.0,
            max_digits=10,
        )
        campo_descuento.set_attributes_from_name('descuento')
        schema_editor.add_field(Pedido, campo_descuento)

    if 'promocion_id' not in columnas:
        campo_promocion = models.ForeignKey(
            Promocion,
            blank=True,
            null=True,
            on_delete=django.db.models.deletion.SET_NULL,
            related_name='pedidos',
        )
        campo_promocion.set_attributes_from_name('promocion')
        schema_editor.add_field(Pedido, campo_promocion)


class Migration(migrations.Migration):
    dependencies = [
        ('pedidos', '0004_pedido_cliente_notificacion_tipo'),
        ('promocion', '0001_initial'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    agregar_campos_si_faltan,
                    migrations.RunPython.noop,
                ),
            ],
            state_operations=[
                migrations.AddField(
                    model_name='pedido',
                    name='descuento',
                    field=models.DecimalField(
                        decimal_places=2,
                        default=0.0,
                        max_digits=10,
                    ),
                ),
                migrations.AddField(
                    model_name='pedido',
                    name='promocion',
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='pedidos',
                        to='promocion.promocion',
                    ),
                ),
            ],
        ),
    ]
