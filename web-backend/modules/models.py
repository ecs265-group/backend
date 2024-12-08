from pydantic import BaseModel


class RegisterUser(BaseModel):
    email: str
    password: str
    public_key: str
    first_name: str
    last_name: str
    organization: str | None = None
    city: str
    state: str
    country_code: str


class LoginUser(BaseModel):
    email: str
    password: str

class SignInitial(BaseModel):
    password: str
