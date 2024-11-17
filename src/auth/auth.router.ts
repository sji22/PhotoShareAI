import express from 'express';
import *as authController from './auth.controller';
import { validateLoginData } from './auth.middleware';
import { authGuard } from './auth.middleware';
const router =express.Router();
router.post('/login',validateLoginData,authController.login);
router.post('/auth/validate',authGuard,authController.validate);

export default router;