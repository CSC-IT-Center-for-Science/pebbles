"""empty message

Revision ID: f0a99f6b5e5e
Revises: he536vdwh29f
Create Date: 2019-05-31 15:57:36.032393

"""

# revision identifiers, used by Alembic.
revision = 'f0a99f6b5e5e'
down_revision = 'he536vdwh29f'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('instance_tokens',
    sa.Column('token', sa.String(length=32), nullable=False),
    sa.Column('instance_id', sa.String(length=32), nullable=True),
    sa.Column('expires_on', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['instance_id'], ['instances.id'], name=op.f('fk_instance_tokens_instance_id_instances')),
    sa.PrimaryKeyConstraint('token', name=op.f('pk_instance_tokens'))
    )
    op.create_unique_constraint(op.f('uq_users_email_id'), 'users', ['email_id'])
    op.create_unique_constraint(op.f('uq_users_eppn'), 'users', ['eppn'])
    op.drop_constraint(u'uq_users_email', 'users', type_='unique')
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(u'uq_users_email', 'users', ['eppn'])
    op.drop_constraint(op.f('uq_users_eppn'), 'users', type_='unique')
    op.drop_constraint(op.f('uq_users_email_id'), 'users', type_='unique')
    op.drop_table('instance_tokens')
    ### end Alembic commands ###
