import React, { useState } from 'react';
import { StyleSheet, Text, View, TouchableOpacity, Alert } from 'react-native';
import QRCodeScanner from 'react-native-qrcode-scanner';
import { RNCamera } from 'react-native-camera';

// Замените YOUR_LOCAL_IP на IP-адрес вашего компьютера в локальной сети
const API_URL = 'http://YOUR_LOCAL_IP:5000/verify';

const App = () => {
  const [scanResult, setScanResult] = useState(null);

  const onSuccess = async (e) => {
    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          qr_data: e.data
        }),
      });

      const result = await response.json();
      
      if (result.valid) {
        Alert.alert(
          'Успешная проверка',
          `Препарат: ${result.drug.manufacturer}\nСерийный номер: ${result.drug.serial_number}\nСрок годности: ${result.drug.expiration_date}`,
          [{ text: 'OK' }]
        );
      } else {
        Alert.alert('Ошибка', result.message);
      }
    } catch (error) {
      Alert.alert('Ошибка', 'Не удалось проверить QR-код');
    }
  };

  return (
    <View style={styles.container}>
      <QRCodeScanner
        onRead={onSuccess}
        flashMode={RNCamera.Constants.FlashMode.auto}
        topContent={
          <Text style={styles.centerText}>
            Наведите камеру на QR-код препарата
          </Text>
        }
        bottomContent={
          <TouchableOpacity style={styles.buttonTouchable}>
            <Text style={styles.buttonText}>Сканировать</Text>
          </TouchableOpacity>
        }
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  centerText: {
    fontSize: 18,
    padding: 32,
    color: '#777',
  },
  buttonTouchable: {
    padding: 16,
  },
  buttonText: {
    fontSize: 21,
    color: 'rgb(0,122,255)',
  },
});

export default App; 