SET LOCAL ROLE appowner;
ALTER TABLE public.service_providers
    ADD COLUMN available_to_all boolean DEFAULT false NOT NULL;
