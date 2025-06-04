export interface Car {
  id: string;
  vin: string;
  make: string;
  model: string;
  year: number;
  price: number;
  mileage: number;
  color: string;
  status: 'available' | 'sold' | 'pending' | 'service';
  dateAdded: string;
}

export interface Customer {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  state: string;
  zipCode: string;
  dateCreated: string;
}

export interface Sale {
  id: string;
  carId: string;
  customerId: string;
  salePrice: number;
  saleDate: string;
  salesPerson: string;
  financeOption?: string;
  status: 'pending' | 'completed' | 'cancelled';
}

export interface DashboardStats {
  totalCars: number;
  availableCars: number;
  soldThisMonth: number;
  totalRevenue: number;
  averagePrice: number;
}
