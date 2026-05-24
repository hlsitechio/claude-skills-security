# GraphQL Field-Level Authorization Reference

Load this when designing or auditing per-field authz in a GraphQL API.

## Why field-level (not just root-level)

REST has one entry point per operation; GraphQL has one entry point per field that can be reached from any traversal. An attacker who reaches a `User` object via `Comment.author` shouldn't get the same fields as a self-lookup on the same user.

```graphql
query Innocent {
  post(id: "...") {
    title
    comments {
      body
      author {
        email             # ← do they see this?
        paymentMethods {  # ← do they see this?
          id
        }
      }
    }
  }
}
```

Three implementation patterns, all valid, each with trade-offs.

## Pattern 1 — Resolver-level checks

Manual check in each resolver:

```ts
const resolvers = {
  User: {
    email: (parent, args, ctx) => {
      if (parent.id !== ctx.user?.id && !ctx.user?.isAdmin) {
        throw new ForbiddenError('Cannot view email');
      }
      return parent.email;
    },
    paymentMethods: (parent, args, ctx) => {
      if (parent.id !== ctx.user?.id) {
        throw new ForbiddenError('Cannot view payment methods');
      }
      return db.paymentMethods.findMany({ where: { userId: parent.id } });
    },
  },
};
```

**Pro:** Explicit, easy to audit per field.
**Con:** Doesn't scale. 50 resolvers × 5 field-level checks each = lots of boilerplate to maintain.

## Pattern 2 — Schema directives

Declare authz declaratively in the schema; implement once.

```graphql
directive @auth(requires: AuthLevel!) on FIELD_DEFINITION

enum AuthLevel {
  PUBLIC      # anyone
  AUTHED      # any logged-in user
  SELF        # current user matches parent.id
  SELF_OR_ADMIN
  ADMIN
}

type User {
  id: ID! @auth(requires: PUBLIC)
  displayName: String! @auth(requires: PUBLIC)
  email: String! @auth(requires: SELF_OR_ADMIN)
  paymentMethods: [PaymentMethod!]! @auth(requires: SELF)
  internalNotes: String @auth(requires: ADMIN)
}
```

Implement the directive (graphql-tools):

```ts
import { mapSchema, getDirective, MapperKind } from '@graphql-tools/utils';

function authDirectiveTransformer(schema) {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
      const authDirective = getDirective(schema, fieldConfig, 'auth')?.[0];
      if (!authDirective) return fieldConfig;
      
      const { requires } = authDirective;
      const { resolve = defaultFieldResolver } = fieldConfig;
      
      fieldConfig.resolve = function (parent, args, ctx, info) {
        switch (requires) {
          case 'PUBLIC':
            break;
          case 'AUTHED':
            if (!ctx.user) throw new ForbiddenError('Auth required');
            break;
          case 'SELF':
            if (!ctx.user || ctx.user.id !== parent.id) throw new ForbiddenError();
            break;
          case 'SELF_OR_ADMIN':
            if (!ctx.user) throw new ForbiddenError();
            if (ctx.user.id !== parent.id && !ctx.user.isAdmin) throw new ForbiddenError();
            break;
          case 'ADMIN':
            if (!ctx.user?.isAdmin) throw new ForbiddenError();
            break;
        }
        return resolve(parent, args, ctx, info);
      };
      return fieldConfig;
    },
  });
}
```

**Pro:** Authz lives next to schema; review is concentrated.
**Con:** Need to maintain the transformer; some edge cases (parent isn't a User) need careful handling.

## Pattern 3 — GraphQL Shield

External library that defines rules and applies them via middleware:

```ts
import { shield, rule, and, or } from 'graphql-shield';

const isAuthenticated = rule()((parent, args, ctx) => ctx.user != null);
const isSelf = rule()((parent, args, ctx) => ctx.user?.id === parent.id);
const isAdmin = rule()((parent, args, ctx) => ctx.user?.isAdmin === true);

const permissions = shield({
  User: {
    email: or(isSelf, isAdmin),
    paymentMethods: isSelf,
    internalNotes: isAdmin,
  },
  Mutation: {
    deleteUser: isAdmin,
    updateProfile: isSelf,
  },
}, {
  fallbackRule: isAuthenticated,   // default: must be authed
  fallbackError: new ForbiddenError('Forbidden'),
});

const schema = applyMiddleware(rawSchema, permissions);
```

**Pro:** Declarative, composable (`and`, `or`, `not`), good defaults via `fallbackRule`.
**Con:** Another dependency; debugging rules can be tricky in complex chains.

## Pattern 4 — Authz at the data layer

Push authz into the database (Postgres RLS) or repository layer; resolvers just call methods that already enforce.

```ts
// db/users.ts
export async function getEmailForUser(targetUserId, requestingUser) {
  if (targetUserId !== requestingUser.id && !requestingUser.isAdmin) {
    return null;   // or throw
  }
  return db.users.findUnique({ where: { id: targetUserId }, select: { email: true } });
}

// resolver
const resolvers = {
  User: {
    email: (parent, args, ctx) => getEmailForUser(parent.id, ctx.user),
  },
};
```

**Pro:** Same authz works for REST, GraphQL, internal tools, batch jobs.
**Con:** Repository layer must be designed for it; can't bolt on after.

## Recommended approach

For most teams: **Pattern 2 (directives) for most fields + Pattern 3 (Shield) for cross-cutting rules + Pattern 4 (repo layer) for the most sensitive data.**

Defense-in-depth: even if a resolver check is missed, the repository check catches it.

## Common bugs

### Bug 1 — Root auth only

```ts
const resolvers = {
  Query: {
    user: requireAuth((parent, { id }, ctx) => db.users.findUnique({ where: { id } })),
  },
  User: {
    // No checks — anyone reaching a User gets every field
    email: (parent) => parent.email,
  },
};
```

Reaching a User via `Comment.author`, `Post.author`, etc. bypasses the root check.

### Bug 2 — Authz check uses arg, not parent

```ts
User: {
  email: (parent, args, ctx) => {
    if (args.userId === ctx.user.id) return parent.email;  // wrong reference
    throw new ForbiddenError();
  },
},
```

Field resolvers receive `parent` (the User object); the check should compare `parent.id` to `ctx.user.id`.

### Bug 3 — Permission check after data fetch

```ts
User: {
  paymentMethods: async (parent, args, ctx) => {
    const data = await db.paymentMethods.findMany({ where: { userId: parent.id } });
    if (ctx.user.id !== parent.id) throw new ForbiddenError();   // too late
    return data;
  },
},
```

Data was already fetched (DB cost, possible logging). Move the check above the fetch.

### Bug 4 — Mutations skipping the check

It's common to have field-level checks on read but not on mutations:

```ts
Mutation: {
  setEmail: (parent, { userId, email }, ctx) => {
    // No check — anyone can change anyone's email
    return db.users.update({ where: { id: userId }, data: { email } });
  },
},
```

Mutations need the same scrutiny — often more, since they're write paths.

### Bug 5 — Error reveals existence

```ts
User: {
  internalNotes: (parent, args, ctx) => {
    if (!ctx.user?.isAdmin) throw new ForbiddenError('Internal notes are admin-only');
    return parent.internalNotes;
  },
},
```

The error message confirms the field exists and reveals authz model. Either return `null` silently for unauthorized, or use a generic error code.

## Audit checklist

For each type in the schema:

1. List fields and tag each: public / authed / self / role-required / admin.
2. Confirm each field has a check matching its tag.
3. For mutations: confirm auth + authz at the start of every resolver.
4. For computed fields fetching other data: check happens BEFORE the fetch.
5. Test the field via a query path other than self-lookup (e.g., reach the User via a comment).
6. Error messages don't disclose which fields exist or what auth is required.
