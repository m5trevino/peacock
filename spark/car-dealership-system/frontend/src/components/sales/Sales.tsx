import React from 'react';
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
  Grid,
  Card,
  CardContent,
} from '@mui/material';
import { Add as AddIcon } from '@mui/icons-material';

const Sales: React.FC = () => {
  const sales = [
    { id: '1', customer: 'John Smith', vehicle: '2023 Honda Civic', price: 25000, date: '2024-06-01', salesperson: 'Mike Wilson', status: 'completed' },
    { id: '2', customer: 'Sarah Johnson', vehicle: '2024 BMW 3 Series', price: 45000, date: '2024-06-02', salesperson: 'Lisa Chen', status: 'pending' },
  ];

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
        <Typography variant="h4" sx={{ color: 'white' }}>
          Sales Management
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          sx={{ bgcolor: 'primary.main' }}
        >
          New Sale
        </Button>
      </Box>

      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={4}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Sales This Month
              </Typography>
              <Typography variant="h4" sx={{ color: '#4caf50' }}>
                34
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Revenue This Month
              </Typography>
              <Typography variant="h4" sx={{ color: '#2196f3' }}>
                $1.2M
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Average Sale Price
              </Typography>
              <Typography variant="h4" sx={{ color: 'white' }}>
                $35,294
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

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
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Sale ID</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Customer</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Vehicle</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Price</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Date</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Salesperson</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Status</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sales.map((sale) => (
              <TableRow key={sale.id} sx={{ '& td': { borderColor: '#333' } }}>
                <TableCell sx={{ color: 'white' }}>#{sale.id}</TableCell>
                <TableCell sx={{ color: 'white' }}>{sale.customer}</TableCell>
                <TableCell sx={{ color: 'white' }}>{sale.vehicle}</TableCell>
                <TableCell sx={{ color: 'white' }}>${sale.price.toLocaleString()}</TableCell>
                <TableCell sx={{ color: 'white' }}>{sale.date}</TableCell>
                <TableCell sx={{ color: 'white' }}>{sale.salesperson}</TableCell>
                <TableCell>
                  <Chip
                    label={sale.status}
                    color={sale.status === 'completed' ? 'success' : 'warning'}
                    size="small"
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default Sales;
