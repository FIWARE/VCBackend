// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/hesusruiz/vcissuer/ent/naturalperson"
	"github.com/hesusruiz/vcissuer/ent/predicate"
)

// NaturalPersonDelete is the builder for deleting a NaturalPerson entity.
type NaturalPersonDelete struct {
	config
	hooks    []Hook
	mutation *NaturalPersonMutation
}

// Where appends a list predicates to the NaturalPersonDelete builder.
func (npd *NaturalPersonDelete) Where(ps ...predicate.NaturalPerson) *NaturalPersonDelete {
	npd.mutation.Where(ps...)
	return npd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (npd *NaturalPersonDelete) Exec(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(npd.hooks) == 0 {
		affected, err = npd.sqlExec(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*NaturalPersonMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			npd.mutation = mutation
			affected, err = npd.sqlExec(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(npd.hooks) - 1; i >= 0; i-- {
			if npd.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = npd.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, npd.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// ExecX is like Exec, but panics if an error occurs.
func (npd *NaturalPersonDelete) ExecX(ctx context.Context) int {
	n, err := npd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (npd *NaturalPersonDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := &sqlgraph.DeleteSpec{
		Node: &sqlgraph.NodeSpec{
			Table: naturalperson.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeString,
				Column: naturalperson.FieldID,
			},
		},
	}
	if ps := npd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, npd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	return affected, err
}

// NaturalPersonDeleteOne is the builder for deleting a single NaturalPerson entity.
type NaturalPersonDeleteOne struct {
	npd *NaturalPersonDelete
}

// Exec executes the deletion query.
func (npdo *NaturalPersonDeleteOne) Exec(ctx context.Context) error {
	n, err := npdo.npd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{naturalperson.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (npdo *NaturalPersonDeleteOne) ExecX(ctx context.Context) {
	npdo.npd.ExecX(ctx)
}
