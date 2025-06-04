import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Chip,
  TextField,
  Grid,
  Card,
  CardContent,
} from '@mui/material';
import { Add as AddIcon, Search as SearchIcon } from '@mui/icons-material';

const Inventory: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');

  // Sample inventory data
  const cars = [
    { id: '1', vin: '1HGBH41JXMN109186', make: 'Honda', model: 'Civic', year: 2023, price: 25000, mileage: 12000, color: 'Blue', status: 'available' },
    { id: '2', vin: '2T1BURHE0JC073123', make: 'Toyota', model: 'Corolla', year: 2022, price: 23000, mileage: 18000, color: 'White', status: 'available' },
    { id: '3', vin: 'WBAPH7G50BNM12345', make: 'BMW', model: '3 Series', year: 2024, price: 45000, mileage: 5000, color: 'Black', status: 'sold' },
    { id: '4', vin: '1G1YY22G135123456', make: 'Chevrolet', model: 'Camaro', year: 2023, price: 35000, mileage: 8000, color: 'Red', status: 'pending' },
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'available': return 'success';
      case 'sold': return 'primary';
      case 'pending': return 'warning';
      default: return 'default';
    }
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
        <Typography variant="h4" sx={{ color: 'white' }}>
          Vehicle Inventory
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          sx={{ bgcolor: 'primary.main' }}
        >
          Add Vehicle
        </Button>
      </Box>

      {/* Search and Filter */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            placeholder="Search by VIN, make, model..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: <SearchIcon sx={{ mr: 1, color: 'gray' }} />,
            }}
            sx={{
              '& .MuiOutlinedInput-root': {
                backgroundColor: '#1a1a1a',
                '& fieldset': { borderColor: '#333' },
                '&:hover fieldset': { borderColor: '#555' },
              },
            }}
          />
        </Grid>
      </Grid>

      {/* Inventory Stats */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={3}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Vehicles
              </Typography>
              <Typography variant="h4" sx={{ color: 'white' }}>
                {cars.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={3}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Available
              </Typography>
              <Typography variant="h4" sx={{ color: '#4caf50' }}>
                {cars.filter(car => car.status === 'available').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={3}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Sold This Month
              </Typography>
              <Typography variant="h4" sx={{ color: '#2196f3' }}>
                {cars.filter(car => car.status === 'sold').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={3}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Value
              </Typography>
              <Typography variant="h4" sx={{ color: 'white' }}>
                ${cars.reduce((sum, car) => sum + car.price, 0).toLocaleString()}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Inventory Table */}
      <TableContainer 
        component={Paper} 
        sx={{ 
          bgcolor: '#1a1a1a', 
          border: '1px solid #333',
        }}
      >
        <Table>
          <TableHead>
            <TableRow sx={{ '& th': { borderColor: '#333' } }}>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>VIN</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Vehicle</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Year</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Mileage</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Price</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Status</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {cars.map((car) => (
              <TableRow key={car.id} sx={{ '& td': { borderColor: '#333' } }}>
                <TableCell sx={{ color: 'white', fontFamily: 'monospace' }}>
                  {car.vin}
                </TableCell>
                <TableCell sx={{ color: 'white' }}>
                  {car.make} {car.model}
                  <br />
                  <Typography variant="caption" color="textSecondary">
                    {car.color}
                  </Typography>
                </TableCell>
                <TableCell sx={{ color: 'white' }}>{car.year}</TableCell>
                <TableCell sx={{ color: 'white' }}>
                  {car.mileage.toLocaleString()} mi
                </TableCell>
                <TableCell sx={{ color: 'white' }}>
                  ${car.price.toLocaleString()}
                </TableCell>
                <TableCell>
                  <Chip
                    label={car.status}
                    color={getStatusColor(car.status) as any}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Button size="small" variant="outlined">
                    Edit
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default Inventory;
