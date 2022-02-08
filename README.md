# rbacCas


## Create Tables Before executing the APIs

1. Members Table
```
CREATE TABLE public.members (
  privilage character varying NULL,
  id integer NOT NULL,
  password character varying NOT NULL,
  name character varying NOT NULL,
  username character varying NOT NULL
);
ALTER TABLE
  public.members
ADD
  CONSTRAINT members_pkey PRIMARY KEY (username)
```

2. Policy (required for casbin)
```
CREATE TABLE public.policy (
  v2 character varying(255) NULL,
  v1 character varying(255) NULL,
  v0 character varying(255) NULL,
  p_type character varying(255) NULL,
  id integer NOT NULL
);
ALTER TABLE
  public.policy
ADD
  CONSTRAINT policy_pkey PRIMARY KEY (id)
```


1. Run the Project
```
    go mod tidy
    go run main.go
```

