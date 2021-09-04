import { NativeModules } from 'react-native';

type Pbkdf2Type = {
  multiply(a: number, b: number): Promise<number>;
};

const { Pbkdf2 } = NativeModules;

export default Pbkdf2 as Pbkdf2Type;
