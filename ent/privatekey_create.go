// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/hesusruiz/vcissuer/ent/privatekey"
	"github.com/hesusruiz/vcissuer/ent/user"
)

// PrivateKeyCreate is the builder for creating a PrivateKey entity.
type PrivateKeyCreate struct {
	config
	mutation *PrivateKeyMutation
	hooks    []Hook
}

// SetKty sets the "kty" field.
func (pkc *PrivateKeyCreate) SetKty(s string) *PrivateKeyCreate {
	pkc.mutation.SetKty(s)
	return pkc
}

// SetAlg sets the "alg" field.
func (pkc *PrivateKeyCreate) SetAlg(s string) *PrivateKeyCreate {
	pkc.mutation.SetAlg(s)
	return pkc
}

// SetNillableAlg sets the "alg" field if the given value is not nil.
func (pkc *PrivateKeyCreate) SetNillableAlg(s *string) *PrivateKeyCreate {
	if s != nil {
		pkc.SetAlg(*s)
	}
	return pkc
}

// SetJwk sets the "jwk" field.
func (pkc *PrivateKeyCreate) SetJwk(u []uint8) *PrivateKeyCreate {
	pkc.mutation.SetJwk(u)
	return pkc
}

// SetCreatedAt sets the "created_at" field.
func (pkc *PrivateKeyCreate) SetCreatedAt(t time.Time) *PrivateKeyCreate {
	pkc.mutation.SetCreatedAt(t)
	return pkc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (pkc *PrivateKeyCreate) SetNillableCreatedAt(t *time.Time) *PrivateKeyCreate {
	if t != nil {
		pkc.SetCreatedAt(*t)
	}
	return pkc
}

// SetUpdatedAt sets the "updated_at" field.
func (pkc *PrivateKeyCreate) SetUpdatedAt(t time.Time) *PrivateKeyCreate {
	pkc.mutation.SetUpdatedAt(t)
	return pkc
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (pkc *PrivateKeyCreate) SetNillableUpdatedAt(t *time.Time) *PrivateKeyCreate {
	if t != nil {
		pkc.SetUpdatedAt(*t)
	}
	return pkc
}

// SetID sets the "id" field.
func (pkc *PrivateKeyCreate) SetID(s string) *PrivateKeyCreate {
	pkc.mutation.SetID(s)
	return pkc
}

// SetUserID sets the "user" edge to the User entity by ID.
func (pkc *PrivateKeyCreate) SetUserID(id string) *PrivateKeyCreate {
	pkc.mutation.SetUserID(id)
	return pkc
}

// SetNillableUserID sets the "user" edge to the User entity by ID if the given value is not nil.
func (pkc *PrivateKeyCreate) SetNillableUserID(id *string) *PrivateKeyCreate {
	if id != nil {
		pkc = pkc.SetUserID(*id)
	}
	return pkc
}

// SetUser sets the "user" edge to the User entity.
func (pkc *PrivateKeyCreate) SetUser(u *User) *PrivateKeyCreate {
	return pkc.SetUserID(u.ID)
}

// Mutation returns the PrivateKeyMutation object of the builder.
func (pkc *PrivateKeyCreate) Mutation() *PrivateKeyMutation {
	return pkc.mutation
}

// Save creates the PrivateKey in the database.
func (pkc *PrivateKeyCreate) Save(ctx context.Context) (*PrivateKey, error) {
	var (
		err  error
		node *PrivateKey
	)
	pkc.defaults()
	if len(pkc.hooks) == 0 {
		if err = pkc.check(); err != nil {
			return nil, err
		}
		node, err = pkc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*PrivateKeyMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = pkc.check(); err != nil {
				return nil, err
			}
			pkc.mutation = mutation
			if node, err = pkc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(pkc.hooks) - 1; i >= 0; i-- {
			if pkc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = pkc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, pkc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from PrivateKeyMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (pkc *PrivateKeyCreate) SaveX(ctx context.Context) *PrivateKey {
	v, err := pkc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (pkc *PrivateKeyCreate) Exec(ctx context.Context) error {
	_, err := pkc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pkc *PrivateKeyCreate) ExecX(ctx context.Context) {
	if err := pkc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (pkc *PrivateKeyCreate) defaults() {
	if _, ok := pkc.mutation.CreatedAt(); !ok {
		v := privatekey.DefaultCreatedAt()
		pkc.mutation.SetCreatedAt(v)
	}
	if _, ok := pkc.mutation.UpdatedAt(); !ok {
		v := privatekey.DefaultUpdatedAt()
		pkc.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pkc *PrivateKeyCreate) check() error {
	if _, ok := pkc.mutation.Kty(); !ok {
		return &ValidationError{Name: "kty", err: errors.New(`ent: missing required field "PrivateKey.kty"`)}
	}
	if _, ok := pkc.mutation.Jwk(); !ok {
		return &ValidationError{Name: "jwk", err: errors.New(`ent: missing required field "PrivateKey.jwk"`)}
	}
	if _, ok := pkc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "PrivateKey.created_at"`)}
	}
	if _, ok := pkc.mutation.UpdatedAt(); !ok {
		return &ValidationError{Name: "updated_at", err: errors.New(`ent: missing required field "PrivateKey.updated_at"`)}
	}
	return nil
}

func (pkc *PrivateKeyCreate) sqlSave(ctx context.Context) (*PrivateKey, error) {
	_node, _spec := pkc.createSpec()
	if err := sqlgraph.CreateNode(ctx, pkc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected PrivateKey.ID type: %T", _spec.ID.Value)
		}
	}
	return _node, nil
}

func (pkc *PrivateKeyCreate) createSpec() (*PrivateKey, *sqlgraph.CreateSpec) {
	var (
		_node = &PrivateKey{config: pkc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: privatekey.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeString,
				Column: privatekey.FieldID,
			},
		}
	)
	if id, ok := pkc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := pkc.mutation.Kty(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: privatekey.FieldKty,
		})
		_node.Kty = value
	}
	if value, ok := pkc.mutation.Alg(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: privatekey.FieldAlg,
		})
		_node.Alg = value
	}
	if value, ok := pkc.mutation.Jwk(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: privatekey.FieldJwk,
		})
		_node.Jwk = value
	}
	if value, ok := pkc.mutation.CreatedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: privatekey.FieldCreatedAt,
		})
		_node.CreatedAt = value
	}
	if value, ok := pkc.mutation.UpdatedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: privatekey.FieldUpdatedAt,
		})
		_node.UpdatedAt = value
	}
	if nodes := pkc.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   privatekey.UserTable,
			Columns: []string{privatekey.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: user.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.user_keys = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// PrivateKeyCreateBulk is the builder for creating many PrivateKey entities in bulk.
type PrivateKeyCreateBulk struct {
	config
	builders []*PrivateKeyCreate
}

// Save creates the PrivateKey entities in the database.
func (pkcb *PrivateKeyCreateBulk) Save(ctx context.Context) ([]*PrivateKey, error) {
	specs := make([]*sqlgraph.CreateSpec, len(pkcb.builders))
	nodes := make([]*PrivateKey, len(pkcb.builders))
	mutators := make([]Mutator, len(pkcb.builders))
	for i := range pkcb.builders {
		func(i int, root context.Context) {
			builder := pkcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*PrivateKeyMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, pkcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, pkcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, pkcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (pkcb *PrivateKeyCreateBulk) SaveX(ctx context.Context) []*PrivateKey {
	v, err := pkcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (pkcb *PrivateKeyCreateBulk) Exec(ctx context.Context) error {
	_, err := pkcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pkcb *PrivateKeyCreateBulk) ExecX(ctx context.Context) {
	if err := pkcb.Exec(ctx); err != nil {
		panic(err)
	}
}
