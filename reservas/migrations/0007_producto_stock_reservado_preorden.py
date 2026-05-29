import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reservas', '0006_pedido_mesero_campos'),
        ('usuarios', '0009_usuario_foto_perfil'),
    ]

    operations = [
        # 1. Agregar stock_reservado a Producto
        migrations.AddField(
            model_name='producto',
            name='stock_reservado',
            field=models.IntegerField(default=0),
        ),

        # 2. Crear modelo Preorden
        migrations.CreateModel(
            name='Preorden',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('estado', models.CharField(
                    choices=[
                        ('apartada', 'Apartada'),
                        ('con_pedido', 'Con Pedido'),
                        ('cancelada', 'Cancelada'),
                        ('entregada', 'Entregada'),
                    ],
                    default='apartada',
                    max_length=20,
                )),
                ('notas', models.TextField(blank=True, null=True)),
                ('total', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('sala', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='preordenes',
                    to='reservas.salatematica',
                )),
                ('mesa', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='preordenes',
                    to='reservas.mesa',
                )),
                ('usuario_mesero', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='preordenes_gestionadas',
                    to='usuarios.usuario',
                )),
            ],
            options={'db_table': 'preorden'},
        ),

        # 3. Crear modelo DetallePreorden
        migrations.CreateModel(
            name='DetallePreorden',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cantidad', models.IntegerField()),
                ('precio_unitario', models.DecimalField(decimal_places=2, max_digits=10)),
                ('subtotal', models.DecimalField(decimal_places=2, max_digits=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('preorden', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='detalles',
                    to='reservas.preorden',
                )),
                ('producto', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    to='reservas.producto',
                )),
            ],
            options={'db_table': 'detalle_preorden'},
        ),
    ]
