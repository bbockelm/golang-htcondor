-- +goose Up
-- +goose StatementBegin

-- One step of grace on the token roll.
--
-- Rolling the nonce and handing the replacement to the helper are two
-- operations and cannot be made one: the server commits the roll, then writes
-- the new token down the control stream of the tunnel it just accepted. A
-- helper that dies in between, or whose control stream fails, keeps a token
-- the server has already moved past -- and there is no way back, because
-- re-issuing needs the authentication that just failed.
--
-- prev_nonce lets that one miss heal. The token the session moved away from
-- stays acceptable for exactly one more dial, which is all a lost delivery
-- needs; using it spends the grace, so a second consecutive miss is refused
-- and the helper ends the session rather than limping.
--
-- NULL means no grace outstanding, which is the state after every successful
-- round trip.
ALTER TABLE jupyter_sessions ADD COLUMN prev_nonce BLOB;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE jupyter_sessions DROP COLUMN prev_nonce;
-- +goose StatementEnd
