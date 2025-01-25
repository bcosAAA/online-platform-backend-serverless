import { Request } from 'express';

export interface UserRegistrationData {
  fullName: string;
  email: string;
  password: string;
  phoneNumber: string;
  profession: string;
  termsAccepted: boolean;
  newsletterSubscription: boolean;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface TypedRequestBody<T> extends Request {
  body: T
}
