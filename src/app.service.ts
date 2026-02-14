import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello() {
    return {
      message: `${process.env.APP_NAME}! Have a good day my friend 😊.`,
      timestamp: new Date(),
    };
  }
}
