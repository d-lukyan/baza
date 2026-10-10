CREATE TABLE IF NOT EXISTS public.avatars
(
    avatar_id serial NOT NULL,
    title character varying(255) COLLATE pg_catalog."default" NOT NULL,
    url text COLLATE pg_catalog."default" NOT NULL,
    gender character varying(50) COLLATE pg_catalog."default" NOT NULL,
    is_premium boolean DEFAULT false,
    CONSTRAINT avatars_pkey PRIMARY KEY (avatar_id)
)

CREATE TABLE IF NOT EXISTS public.feed_posts
(
    post_id serial NOT NULL,
    username text COLLATE pg_catalog."default" NOT NULL,
    message text COLLATE pg_catalog."default" NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT feed_posts_pkey PRIMARY KEY (post_id)
)

CREATE TABLE IF NOT EXISTS public.messages
(
    message_id serial NOT NULL,
    sender_id uuid NOT NULL,
    receiver_id uuid NOT NULL,
    content text COLLATE pg_catalog."default" NOT NULL,
    sent_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    is_read boolean DEFAULT false,
    CONSTRAINT messages_pkey PRIMARY KEY (message_id),
    CONSTRAINT messages_receiver_id_fkey FOREIGN KEY (receiver_id)
        REFERENCES public.users (user_id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT messages_sender_id_fkey FOREIGN KEY (sender_id)
        REFERENCES public.users (user_id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

CREATE TABLE IF NOT EXISTS public.password_resets
(
    reset_id serial NOT NULL,
    user_id uuid NOT NULL,
    token text COLLATE pg_catalog."default" NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used boolean DEFAULT false,
    CONSTRAINT password_resets_pkey PRIMARY KEY (reset_id),
    CONSTRAINT fk_reset_user FOREIGN KEY (user_id)
        REFERENCES public.users (user_id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

CREATE TABLE IF NOT EXISTS public.store_stock
(
    product_id integer,
    store_id integer,
    units integer
)

CREATE TABLE IF NOT EXISTS public.users
(
    user_id uuid NOT NULL DEFAULT gen_random_uuid(),
    username text COLLATE pg_catalog."default" NOT NULL,
    email text COLLATE pg_catalog."default" NOT NULL,
    password text COLLATE pg_catalog."default" NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    role text COLLATE pg_catalog."default" DEFAULT 'user'::text,
    bio text COLLATE pg_catalog."default",
    CONSTRAINT users_pkey PRIMARY KEY (user_id),
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_username_key UNIQUE (username),
    CONSTRAINT users_role_check CHECK (role = ANY (ARRAY['user'::text, 'admin'::text]))
)

INSERT INTO users (username, password) 
VALUES ('admin', 'password') 
ON CONFLICT (username) DO NOTHING;
