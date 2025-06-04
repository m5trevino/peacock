import React from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
} from '@mui/material';
import { Add as AddIcon } from '@mui/icons-material';

const Finance: React.FC = () => {
  const loanApplications = [
    { id: '1', customer: 'John Smith', amount: 25000, rate: '3.9%', term: '60 months', status: 'approved' },
    { id: '2', customer: 'Sarah Johnson', amount: 45000, rate: '4.2%', term: '72 months', status: 'pending' },
  ];

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
        <Typography variant="h4" sx={{ color: 'white' }}>
          Finance Management
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          sx={{ bgcolor: 'primary.main' }}
        >
          New Application
        </Button>
      </Box>

      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={3}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Active Loans
              </Typography>
              <Typography variant="h4" sx={{ color: '#4caf50' }}>
                156
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={3}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Pending Applications
              </Typography>
              <Typography variant="h4" sx={{ color: '#ff9800' }}>
                12
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={3}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Average Rate
              </Typography>
              <Typography variant="h4" sx={{ color: '#2196f3' }}>
                4.1%
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={3}>
          <Card sx={{ bgcolor: '#1a1a1a', border: '1px solid #333' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Financed
              </Typography>
              <Typography variant="h4" sx={{ color: 'white' }}>
                $8.7M
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
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Application ID</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Customer</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Loan Amount</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Interest Rate</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Term</TableCell>
              <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Status</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loanApplications.map((loan) => (
              <TableRow key={loan.id} sx={{ '& td': { borderColor: '#333' } }}>
                <TableCell sx={{ color: 'white' }}>#{loan.id}</TableCell>
                <TableCell sx={{ color: 'white' }}>{loan.customer}</TableCell>
                <TableCell sx={{ color: 'white' }}>${loan.amount.toLocaleString()}</TableCell>
                <TableCell sx={{ color: 'white' }}>{loan.rate}</TableCell>
                <TableCell sx={{ color: 'white' }}>{loan.term}</TableCell>
                <TableCell>
                  <Chip
                    label={loan.status}
                    color={loan.status === 'approved' ? 'success' : 'warning'}
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

export default Finance;
