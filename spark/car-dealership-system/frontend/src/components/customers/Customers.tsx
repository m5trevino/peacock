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
  Avatar,
  Chip,
} from '@mui/material';
import { Add as AddIcon, Person } from '@mui/icons-material';

const Customers: React.FC = () => {
  const customers = [
    { id: '1', name: 'John Smith', email: 'john@email.com', phone: '(555) 123-4567', city: 'San Francisco', purchases: 2, status: 'active' },
    { id: '2', name: 'Sarah Johnson', email: 'sarah@email.com', phone: '(555) 234-5678', city: 'Oakland', purchases: 1, status: 'active' },
    { id: '3', name: 'Mike Davis', email: 'mike@email.com', phone: '(555) 345-6789', city: 'San Jose', purchases: 0, status: 'prospect' },
  ];

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
        <Typography variant="h4" sx={{ color: 'white' }}>
          Customer Management
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          sx={{ bgcolor: 'primary.main' }}
        >
          Add Customer
        </Button>
      </Box>

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
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Customer</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Contact</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Location</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Purchases</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Status</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {customers.map((customer) => (
              <TableRow key={customer.id} sx={{ '& td': { borderColor: '#333' } }}>
                <TableCell sx={{ color: 'white' }}>
                  <Box display="flex" alignItems="center" gap={2}>
                    <Avatar>
                      <Person />
                    </Avatar>
                    <Box>
                      <Typography variant="body1">{customer.name}</Typography>
                      <Typography variant="caption" color="textSecondary">
                        ID: {customer.id}
                      </Typography>
                    </Box>
                  </Box>
                </TableCell>
                <TableCell sx={{ color: 'white' }}>
                  <Box>
                    <Typography variant="body2">{customer.email}</Typography>
                    <Typography variant="caption" color="textSecondary">
                      {customer.phone}
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell sx={{ color: 'white' }}>{customer.city}</TableCell>
                <TableCell sx={{ color: 'white' }}>{customer.purchases}</TableCell>
                <TableCell>
                  <Chip
                    label={customer.status}
                    color={customer.status === 'active' ? 'success' : 'warning'}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Button size="small" variant="outlined">
                    View
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

export default Customers;
