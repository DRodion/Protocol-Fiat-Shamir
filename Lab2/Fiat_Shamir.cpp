#include <iostream>
#include <typeinfo>

#include "../cryptopp860/cryptlib.h"
#include "../cryptopp860/modes.h"
#include "../cryptopp860/filters.h"
#include "../cryptopp860/osrng.h" // PNG AutoSeededRandomPool
#include "../cryptopp860/integer.h"
#include "../cryptopp860/nbtheory.h"


using namespace CryptoPP;
using namespace std;

//количество раундов
const unsigned int COUNT_ROUND = 5;

//размер простых чисел в битах
const unsigned int bytes = 64;


//функция генерации простого числа
Integer get_prime(unsigned int bytes) {
    AutoSeededRandomPool prng;
    Integer x;
    do {
        x.Randomize(prng, bytes);
    } while (!IsPrime(x));

    return x;
}

//функция проверки числа на простоту
Integer simple(const Integer n) {

    for (int i = 2; i <= n.SquareRoot(); i++)
        if ((n % i) == 0) 
            return 0;
    return 1;

}


//функция проверки взаимно просты два числа
Integer is_simple_n_s(Integer n, Integer s) {
    if (Integer::Gcd(s, n) == 1) // основано на проверке НОД 2х чисел
        return 1;
    else
        return 0;
}

//предварительный этап
class Trust_Center_T {
private:
    Integer n;
public:
    //функция создания числа n
    Integer create_N(Integer p, Integer q) {
        n = p * q;
        cout << "Доверенный центр публикует модель схемы. n = " << n << endl;
        return n;
    }
};


//класс пользователя
class User_P {
private:
    Integer S;
    Integer S_error;
    Integer V;
    Integer r;
    Integer x;
    Integer y;

    AutoSeededRandomPool rng;
    enum Integer::RandomNumberType rnType = Integer::ANY;
    const Integer  equiv = Integer::Zero();
    const Integer mod = Integer::One();
public:
    //функция вычисления открытого ключа V и генерации закрытого ключа S
    Integer choice_V(Integer n) {
        cout << "User: Выбирает секретный ключ S =  ";
        do {
            S = Integer::Integer(rng, 1, n-1, rnType, equiv, mod); // генерация закрытого ключа S в интервале от 1 до n-1

            if (is_simple_n_s(n, S) == 1) {
                break;
            }
        } while (true);
        cout << S << endl;

        cout << "User: Вычисление открытого ключа V на основе секретного ключа S..." << endl;
        V = a_exp_b_mod_c(S,2,n); // V = (S ^ 2) mod n
        cout << "User: Открытый ключ V = " << V << endl;
        return V;
    }

    Integer step_1(Integer n) {
        // step 1
        r = Integer::Integer(rng, 1, n - 1, rnType, equiv, mod);// генерация r в интервале от 1 до n-1
        cout << "User: Выбирает случайное число r = " << r << endl;
        cout << "User: Генерация x..." <<  endl;
        x = a_exp_b_mod_c(r, 2, n);// x = (r ^ 2) mod n 
        cout << "User: Значение x = " << x << endl;
        return x;
    }

    Integer step_3(Integer n, Integer e, int status) {
        // step 3
        Integer pow_P;
        if (status == 1) {
            pow_P = a_exp_b_mod_c(S, e, n);// pow_p = (S ^ e) mod n 
            cout << "User: Вычисление y..." << endl;
            y = a_times_b_mod_c(r,pow_P, n); // y = (r * pow_p) mod n
            cout << "User: Вычисленное значение y = " << y <<  endl;
            return y;
        }
        else if (status == 0) {
            S_error = 14758932;
            cout << "Предполагаемый секретный ключ S = " << S_error << endl;
            pow_P = a_exp_b_mod_c(S_error, e, n);// pow_p = (S ^ e) mod n 
            cout << "User: Вычисление y..." << endl;
            y = a_times_b_mod_c(r, pow_P, n); // y = (r * pow_p) mod n
            cout << "User: Вычисленное значение y = " << y << endl;
            return y;
        }
        
    }
};

//рабочий этап
class Check_V {
private:
    Integer r;
    Integer x;
    Integer e;
    Integer y_from_p;
    Integer y_from_v;

    AutoSeededRandomPool rng;
    Integer::RandomNumberType rnType = Integer::ANY;
    const Integer  equiv = Integer::Zero();
    const Integer mod = Integer::One();
public:
    Integer check(User_P& P, Integer n, Integer OpenKey, int status) {
        // step 1
        cout << "1.0 Шаг" << endl;
        x = P.step_1(n);
        cout << "Check: Полученное значение x = " << x << endl;

        // step 2
        cout << "2.0 Шаг" << endl;
        cout << "Check: Выбор случайного бита..." << endl;
        e = Integer::Integer(rng, 0, 1, rnType, equiv, mod); // генерация r в интервале от 0 до 1
        cout << "Check: Случайный бит e = " << e << endl;

        // step 3
        cout << "3.0 Шаг" << endl;
        cout << "Check: Отправка User случайного бита e..." << endl;
        y_from_p = P.step_3(n, e, status);
        cout << "Check: Получение от User y_1 = " << y_from_p << endl;        

        // step 4
        cout << "4.0 Шаг" << endl;

        y_from_v = a_times_b_mod_c(x, OpenKey, n);// y = (x * V) mod n, где V = OpenKey


        Integer pow_y2 = a_exp_b_mod_c(y_from_p, 2, n); //y^2

        if (y_from_p == 0) {
            cout << "Check: User не знет секретный ключ S." << endl;
            return 0;
        }
        else {
            cout << "Check: Проверка равенства..." << endl;
            cout << "Check: Вычисление y_2 на основе открытого ключа V..." << endl;
            

            cout << "Check: Вычисленное значение y_2 = " << y_from_v << endl;

            if (e == 0) {
                cout << "Check: Проверка ключей " << pow_y2 << " и " << x << endl;
                if (pow_y2 == x) {
                    cout << "Check: Verify!" << endl;
                    return 1;
                }
                else {
                    cout << "Check: Error!" << endl;
                    return 0;
                }
            }
            else {
                cout << "Check: Проверка ключей " << a_exp_b_mod_c(y_from_p, 2, n) << " и " << a_times_b_mod_c(x, OpenKey, n) << endl;
                if (pow_y2 == y_from_v) {
                    cout << "Check: Verify!" << endl;
                    return 1;
                }
                else {
                    cout << "Check: Error!" << endl;
                    return 0;
                }
            }          
        }  
    }
};


int main(int argc, char* argv[]){
    setlocale(LC_ALL, "rus");

    Integer p = get_prime(bytes);
    Integer q = get_prime(bytes);

    cout << "Простое число p = " << p << endl;
    cout << "Простое число q = " << q << endl;

    // корректная аутентификация
    //int status = 1;
    // НЕкорректная аутентификация
    int status = 0;

    Integer N, OpenKey, i, stat;

    Trust_Center_T T;
    User_P P;
    Check_V V;


    N = T.create_N(p, q); //получение N
    OpenKey = P.choice_V(N); //получение V

    for (i = 0; i < COUNT_ROUND; i++) {
        cout << endl;
        cout << "Номер раунда: " << i + 1 << endl;
        stat = V.check(P, N, OpenKey, status);
        if (stat == 1) {
            cout << "Раунд завершился корректно." << endl;
        }
        else {
            cout << "Раунд завершился НЕкорректно." << endl;
            break;
        }
    }


    system("pause");
    return 0;
}